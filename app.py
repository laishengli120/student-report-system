import os
import time
import sqlite3
import pandas as pd
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, g) 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime

from ai_service import (get_ai_config, generate_single_comment, TYPE_OPTIONS,
                        SAFETY_NOTICE_TEMPLATES, render_safety_notice_html,
                        generate_safety_notice)

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) 
app.config['DATABASE'] = os.path.join(app.instance_path, 'school_data.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls'}

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123" 
DEFAULT_GRADE_RULES = "90=A\n80=B\n60=C\n0=D"

try:
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except OSError as e:
    pass 

# --- Database Helper Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db(app_context=None):
    def execute_init(db):
        cursor = db.cursor()
        
        # 1. Create tables if they don't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS student_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            chinese_score REAL,
            math_score REAL,
            english_score REAL,
            science_score REAL,
            morality_score REAL,
            final_remarks TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            signature_img TEXT,
            signed_at TIMESTAMP
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # 2. Settings Table for storing dynamic dates
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        
        # Default Settings (Inserted only if not exist)
        defaults = {
            'holiday_start': '2026年1月31日',
            'next_term_report': '2026年3月4日',
            'next_term_start': '2026年3月5日',
            'ai_api_key': '',
            'ai_base_url': 'https://api.deepseek.com',
            'ai_model': 'deepseek-v4-flash',
            'grade_rules': DEFAULT_GRADE_RULES,
            'safety_notice': render_safety_notice_html(SAFETY_NOTICE_TEMPLATES['winter']),
            'safety_notice_template': 'winter',
            'score_display_mode': 'grade_only',
        }
        for k, v in defaults.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))


        # 3. Migration: Add missing columns if they don't exist
        new_columns = {
            'signature_img': 'TEXT',
            'signed_at': 'TIMESTAMP',
            'science_score': 'REAL',
            'morality_score': 'REAL'
        }

        for col, dtype in new_columns.items():
            try:
                cursor.execute(f"SELECT {col} FROM student_reports LIMIT 1")
            except sqlite3.OperationalError:
                print(f"Adding missing column '{col}' to student_reports...")
                cursor.execute(f"ALTER TABLE student_reports ADD COLUMN {col} {dtype}")

        # 4. Migration: AI review workflow columns
        ai_columns = {
            'position': 'TEXT',
            'status': 'TEXT',
            'ai_remarks': 'TEXT',
            'brief_description': 'TEXT'
        }
        for col, dtype in ai_columns.items():
            try:
                cursor.execute(f"SELECT {col} FROM student_reports LIMIT 1")
            except sqlite3.OperationalError:
                print(f"Adding missing column '{col}' to student_reports...")
                cursor.execute(f"ALTER TABLE student_reports ADD COLUMN {col} {dtype}")

        # Backfill status for existing records
        cursor.execute("UPDATE student_reports SET status = 'published' WHERE status IS NULL OR status = ''")

        # 5. Create default admin
        cursor.execute("SELECT id FROM admins WHERE username = ?", (DEFAULT_ADMIN_USERNAME,))
        if cursor.fetchone() is None:
            hashed_password = generate_password_hash(DEFAULT_ADMIN_PASSWORD, method='pbkdf2:sha256')
            cursor.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (DEFAULT_ADMIN_USERNAME, hashed_password)
            )
        
        db.commit()

    if app_context:
        with app_context:
            db = get_db()
            execute_init(db)
    else:
        with app.app_context():
            db = get_db()
            execute_init(db)


# Initialize/Migrate DB on start
if not os.path.exists(app.config['DATABASE']):
    init_db(app_context=app.app_context())
else:
    init_db(app_context=app.app_context())

# --- File Upload Helper ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('请先登录管理员账户。', 'error')
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def parse_grade_rules(raw_rules, use_default=True):
    rules = []
    for line in (raw_rules or DEFAULT_GRADE_RULES).splitlines():
        text = line.strip()
        if not text:
            continue
        if '=' in text:
            threshold_text, label = text.split('=', 1)
        elif ':' in text:
            threshold_text, label = text.split(':', 1)
        else:
            continue
        try:
            threshold = float(threshold_text.strip())
        except ValueError:
            continue
        label = label.strip()
        if label:
            rules.append({'threshold': threshold, 'label': label})
    if not rules and use_default:
        rules = [
            {'threshold': 90, 'label': '优秀'},
            {'threshold': 80, 'label': '良好'},
            {'threshold': 60, 'label': '合格'},
            {'threshold': 0, 'label': '待努力'}
        ]
    return sorted(rules, key=lambda item: item['threshold'], reverse=True)

def score_to_grade(score, rules):
    if score is None:
        return ''
    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        return ''
    for rule in rules:
        if numeric_score >= rule['threshold']:
            return rule['label']
    return rules[-1]['label'] if rules else ''

def add_grade_fields(report_data, settings):
    rules = parse_grade_rules(settings.get('grade_rules'))
    score_fields = ['chinese_score', 'math_score', 'english_score', 'science_score', 'morality_score']
    for field in score_fields:
        report_data[f"{field.replace('_score', '')}_grade"] = score_to_grade(report_data.get(field), rules)
    return report_data

# --- Routes ---
import subprocess
import hmac
import hashlib
import os

@app.route('/git-update', methods=['POST'])
def git_update():
  # 可选：验证 GitHub 签名
  signature = request.headers.get('X-Hub-Signature-256')
  secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '').encode()
  if secret:
      expected = 'sha256=' + hmac.new(secret, request.data,
hashlib.sha256).hexdigest()
      if not hmac.compare_digest(signature, expected):
          return 'Invalid signature', 403

  # 执行 git pull
  subprocess.run(['git', '-C', '/home/huangmengqian/student-report-system', 'pull',
'origin', 'main'])
  subprocess.run(['touch',
'/var/www/huangmengqian_pythonanywhere_com_wsgi.py'])
  return 'OK', 200

@app.route('/')
def index():
    return redirect(url_for('parent_query_page'))

@app.route('/parent')
def parent_query_page():
    return render_template('parent_query.html')

@app.route('/api/get_report', methods=['GET'])
def get_report_api():
    student_name_query = request.args.get('name')
    if not student_name_query:
        return jsonify({'error': '未提供学生姓名。'}), 400

    db = get_db()
    cursor = db.cursor()
    
    # Fetch Student Data
    cursor.execute("SELECT * FROM student_reports WHERE student_name = ? AND status = 'published' ORDER BY uploaded_at DESC LIMIT 1",
                   (student_name_query,))
    report = cursor.fetchone()

    if report:
        report_data = dict(report)
        
        # Fetch Dynamic Settings
        cursor.execute("SELECT key, value FROM settings")
        settings = {row['key']: row['value'] for row in cursor.fetchall()}
        
        # Fallbacks just in case
        holiday_start = settings.get('holiday_start', '____年__月__日')
        next_term_report = settings.get('next_term_report', '____年__月__日')
        next_term_start = settings.get('next_term_start', '____年__月__日')
        report_data = add_grade_fields(report_data, settings)
        # Auto-detect 寒假/暑假 from holiday_start month
        holiday_label = '寒假'
        import re
        month_match = re.search(r'(\d{1,2})月', holiday_start)
        if month_match:
            month = int(month_match.group(1))
            if 6 <= month <= 8:
                holiday_label = '暑假'
            elif 1 <= month <= 2:
                holiday_label = '寒假'

        # Construct HTML dynamically
        announcement_html = f"""
        <p><strong id="report-student-name-salutation" class="text-red-800 text-lg" style="font-family: 'KaiTi', '楷体', serif;">{report_data['student_name']}</strong> 同学之家长：</p>
        <p>您好！</p>
        <p class="indent-8">
            在您的大力支持和配合下，您的孩子在我校已经圆满完成了本学期的学习任务，在此代表学校和各位任课老师，向家长表示衷心的感谢！愿新的学期能继续得到您的支持。
        </p>
        <p class="indent-8">
            根据县教育局通知，我校{holiday_label}定于：<span class="font-bold underline decoration-red-800 decoration-2">{holiday_start}正式放假</span>，下学期<span class="font-bold underline decoration-red-800 decoration-2">{next_term_report}开学报到，{next_term_start}正式开学上课</span>。
        </p>
        <p class="indent-8">
            现将本学期贵子女的在校情况及相关事宜通知如下，请家长配合做好孩子在假期间的教育工作。
        </p>
        """
        
        report_data['announcement_html'] = announcement_html
        report_data['safety_notice_html'] = settings.get('safety_notice', '')
        report_data['score_display_mode'] = settings.get('score_display_mode', 'grade_only')
        return jsonify(report_data)
    else:
        return jsonify({'error': f'未找到姓名为 "{student_name_query}" 的学生成绩信息。'}), 404

@app.route('/api/submit_signature', methods=['POST'])
def submit_signature():
    data = request.json
    student_name = data.get('student_name')
    signature_img = data.get('signature_img')

    if not student_name or not signature_img:
        return jsonify({'error': '数据不完整'}), 400

    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("SELECT id FROM student_reports WHERE student_name = ? AND status = 'published' ORDER BY uploaded_at DESC LIMIT 1", (student_name,))
        row = cursor.fetchone()
        
        if row:
            report_id = row['id']
            cursor.execute("""
                UPDATE student_reports 
                SET signature_img = ?, signed_at = ? 
                WHERE id = ?
            """, (signature_img, datetime.now(), report_id))
            db.commit()
            return jsonify({'success': True, 'message': '签名提交成功'})
        else:
            return jsonify({'error': '找不到该学生的记录'}), 404
            
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    return redirect(url_for('admin_upload_page', section='time'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin_user = cursor.fetchone()

        if admin_user and check_password_hash(admin_user['password_hash'], password):
            session['admin_logged_in'] = True
            session['username'] = admin_user['username']
            flash('登录成功！', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('admin_dashboard'))
        else:
            flash('用户名或密码错误。', 'error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('username', None)
    flash('您已成功登出。', 'success')
    return redirect(url_for('admin_login'))


# --- New Route for updating settings ---
@app.route('/admin/settings', methods=['POST'])
@login_required
def admin_update_settings():
    db = get_db()
    cursor = db.cursor()
    
    fields = ['holiday_start', 'next_term_report', 'next_term_start']
    
    try:
        for field in fields:
            value = request.form.get(field)
            if value:
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (field, value.strip()))
        db.commit()
        flash('通知书时间参数已更新！', 'success')
    except Exception as e:
        db.rollback()
        flash(f'设置更新失败: {str(e)}', 'error')
        
    return redirect(url_for('admin_upload_page', section='time'))


@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def admin_upload_page():
    # Handle Upload POST
    if request.method == 'POST':
        use_ai_review = request.form.get('use_ai_review') == '1'
        if 'excel_file' not in request.files:
            flash('未检测到文件部分。', 'error')
            return redirect(url_for('admin_upload_page', section='upload'))
        file = request.files['excel_file']
        if file.filename == '':
            flash('未选择任何文件。', 'error')
            return redirect(url_for('admin_upload_page', section='upload'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(filepath)
                df = pd.read_excel(filepath)

                required_conceptual_cols = ['姓名', '语文', '数学', '英语']
                actual_columns = [str(col).strip() for col in df.columns]

                missing_cols = [req_col for req_col in required_conceptual_cols if req_col not in actual_columns]
                if missing_cols:
                    flash(f'Excel文件缺少核心列: {", ".join(missing_cols)}。', 'error')
                    return redirect(url_for('admin_upload_page', section='upload'))

                db = get_db()
                cursor = db.cursor()
                records_processed = 0
                error_in_batch = False

                for index, row in df.iterrows():
                    try:
                        student_name = str(row['姓名']).strip()
                        if not student_name:
                            continue

                        if use_ai_review:
                            cursor.execute("DELETE FROM student_reports WHERE student_name = ? AND status = 'draft'", (student_name,))
                        else:
                            cursor.execute("DELETE FROM student_reports WHERE student_name = ?", (student_name,))

                        data_to_insert = {
                            'student_name': student_name,
                            'chinese_score': pd.to_numeric(row.get('语文'), errors='coerce'),
                            'math_score': pd.to_numeric(row.get('数学'), errors='coerce'),
                            'english_score': pd.to_numeric(row.get('英语'), errors='coerce'),
                            'science_score': pd.to_numeric(row.get('科学'), errors='coerce'),
                            'morality_score': pd.to_numeric(row.get('道德与法治'), errors='coerce'),
                            'final_remarks': str(row.get('期末评语', '')).strip() if pd.notna(row.get('期末评语')) else None,
                            'position': str(row.get('职位', '')).strip() if pd.notna(row.get('职位')) else None,
                            'brief_description': None
                        }

                        for key, value in data_to_insert.items():
                            if pd.isna(value):
                                data_to_insert[key] = None

                        status_value = 'draft' if use_ai_review else 'published'
                        cursor.execute(f"""
                            INSERT INTO student_reports (
                                student_name, chinese_score, math_score, english_score,
                                science_score, morality_score, final_remarks, position, brief_description, status
                            )
                            VALUES (
                                :student_name, :chinese_score, :math_score, :english_score,
                                :science_score, :morality_score, :final_remarks, :position, :brief_description, '{status_value}'
                            )
                        """, data_to_insert)
                        records_processed += 1
                    except Exception as e:
                        flash(f'处理Excel第 {index+2} 行 ({row.get("姓名", "未知姓名")}) 时发生一般错误: {str(e)}', 'error')
                        error_in_batch = True; break

                if error_in_batch:
                    db.rollback()
                else:
                    db.commit()
                    if use_ai_review:
                        flash(f'文件上传成功！共处理了 {records_processed} 条学生记录，请审核并生成评语。', 'success')
                    else:
                        flash(f'文件上传成功！共处理了 {records_processed} 条学生记录，已直接发布。', 'success')

            except Exception as e:
                flash(f'处理文件时发生未知错误: {str(e)}', 'error')
                if 'db' in locals() and db and not error_in_batch:
                    db.rollback()
            finally:
                if 'filepath' in locals() and os.path.exists(filepath):
                    try: os.remove(filepath)
                    except OSError: pass
            if use_ai_review:
                return redirect(url_for('admin_review_page'))
            else:
                return redirect(url_for('admin_upload_page', section='upload'))
        else:
            flash('文件类型不被允许。', 'error')
            return redirect(url_for('admin_upload_page', section='upload'))
    
    # Handle GET: Show Page + Settings
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    return render_template('admin_upload.html', settings=settings)


# --- AI Settings Route ---
@app.route('/admin/ai_settings', methods=['POST'])
@login_required
def admin_update_ai_settings():
    db = get_db()
    cursor = db.cursor()
    fields = ['ai_api_key', 'ai_base_url', 'ai_model']
    for field in fields:
        value = request.form.get(field, '').strip()
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (field, value))
    db.commit()
    flash('AI接口设置已更新！', 'success')
    return redirect(url_for('admin_upload_page', section='ai'))

@app.route('/admin/grade_settings', methods=['POST'])
@login_required
def admin_update_grade_settings():
    raw_rules = request.form.get('grade_rules', '').strip()
    score_display_mode = request.form.get('score_display_mode', 'grade_only').strip()
    if score_display_mode not in ('grade_only', 'score_only', 'both'):
        score_display_mode = 'grade_only'

    parsed_rules = parse_grade_rules(raw_rules, use_default=False)
    if not raw_rules or not parsed_rules:
        flash('等级规则不能为空，请按"分数=等级"的格式填写。', 'error')
        return redirect(url_for('admin_upload_page', section='grade'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        ('grade_rules', raw_rules)
    )
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        ('score_display_mode', score_display_mode)
    )
    db.commit()
    flash('分数等级映射规则已更新！', 'success')
    return redirect(url_for('admin_upload_page', section='grade'))


# --- Review Page ---
@app.route('/admin/review')
@login_required
def admin_review_page():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'ai_api_key'")
    ai_key_row = cursor.fetchone()
    ai_configured = bool(ai_key_row and ai_key_row['value'] and ai_key_row['value'].strip())
    return render_template('admin_review.html', ai_configured=ai_configured, type_options=TYPE_OPTIONS)


@app.route('/api/review_data')
@login_required
def get_review_data():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, student_name, position, chinese_score, math_score,
               english_score, science_score, morality_score, final_remarks, ai_remarks, brief_description
        FROM student_reports WHERE status = 'draft'
        ORDER BY id
    """)
    drafts = [dict(row) for row in cursor.fetchall()]
    for d in drafts:
        raw = (d.get('brief_description') or '').strip()
        d['types'] = raw.split('|') if raw else []
    return jsonify(drafts)


@app.route('/api/generate_comment/<int:student_id>', methods=['POST'])
@login_required
def generate_single_comment_api(student_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM student_reports WHERE id = ? AND status = 'draft'", (student_id,))
    student = cursor.fetchone()
    if not student:
        return jsonify({'error': '找不到该学生的草稿记录'}), 404

    ai_config = get_ai_config(db)
    if not ai_config:
        return jsonify({'error': '请先在管理页面配置AI接口密钥。'}), 400

    raw = (student['brief_description'] or '').strip()
    types = raw.split('|') if raw else []
    comment, error = generate_single_comment(
        student['student_name'], student['position'], types, ai_config
    )
    if error:
        return jsonify({'error': error}), 500

    cursor.execute("""
        UPDATE student_reports SET final_remarks = ?, ai_remarks = ? WHERE id = ?
    """, (comment, comment, student_id))
    db.commit()
    return jsonify({'success': True, 'comment': comment})


@app.route('/api/generate_all_comments', methods=['POST'])
@login_required
def generate_all_comments_api():
    db = get_db()
    cursor = db.cursor()

    ai_config = get_ai_config(db)
    if not ai_config:
        return jsonify({'error': '请先在管理页面配置AI接口密钥。'}), 400

    cursor.execute("SELECT * FROM student_reports WHERE status = 'draft' ORDER BY id")
    drafts = cursor.fetchall()
    if not drafts:
        return jsonify({'error': '没有待审核的学生记录。'}), 400

    results = []
    for i, student in enumerate(drafts):
        if i > 0:
            time.sleep(0.4)
        raw = (student['brief_description'] or '').strip()
        types = raw.split('|') if raw else []
        comment, error = generate_single_comment(
            student['student_name'], student['position'], types, ai_config
        )
        if comment:
            cursor.execute("""
                UPDATE student_reports SET final_remarks = ?, ai_remarks = ? WHERE id = ?
            """, (comment, comment, student['id']))
            results.append({
                'id': student['id'],
                'name': student['student_name'],
                'success': True,
                'comment': comment
            })
        else:
            results.append({
                'id': student['id'],
                'name': student['student_name'],
                'success': False,
                'error': error
            })
    db.commit()
    return jsonify({'results': results})


@app.route('/api/update_comment/<int:student_id>', methods=['POST'])
@login_required
def update_comment_api(student_id):
    data = request.json
    new_comment = data.get('comment', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE student_reports SET final_remarks = ? WHERE id = ? AND status = 'draft'
    """, (new_comment, student_id))
    db.commit()
    return jsonify({'success': True})


@app.route('/api/update_types/<int:student_id>', methods=['POST'])
@login_required
def update_types_api(student_id):
    data = request.json
    types = data.get('types', [])
    type_str = '|'.join(types) if types else ''
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE student_reports SET brief_description = ? WHERE id = ? AND status = 'draft'
    """, (type_str, student_id))
    db.commit()
    return jsonify({'success': True})


@app.route('/api/signature_dashboard')
@login_required
def signature_dashboard():
    """返回所有已发布学生的签收状态"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, student_name, position, signature_img, signed_at,
               chinese_score, math_score, english_score, science_score, morality_score
        FROM student_reports
        WHERE status = 'published'
        ORDER BY student_name
    """)
    rows = cursor.fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d['signed'] = bool(d['signature_img'] and d['signature_img'].strip())
        d['signed_at'] = str(d['signed_at']) if d['signed_at'] else None
        # 不传完整的 base64 图片数据，只传缩略信息
        sig = d.get('signature_img') or ''
        if len(sig) > 200:
            d['signature_thumb'] = sig[:80] + '…'
            d['has_signature_img'] = True
        else:
            d['signature_thumb'] = sig
            d['has_signature_img'] = bool(sig)
        d.pop('signature_img', None)
        results.append(d)
    return jsonify({
        'students': results,
        'total': len(results),
        'signed_count': sum(1 for r in results if r['signed']),
        'unsigned_count': sum(1 for r in results if not r['signed'])
    })


@app.route('/api/signature_detail/<int:student_id>')
@login_required
def signature_detail(student_id):
    """返回单个学生的完整签名图片"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, student_name, signature_img, signed_at FROM student_reports WHERE id = ? AND status = 'published'",
        (student_id,)
    )
    row = cursor.fetchone()
    if not row:
        return jsonify({'error': '找不到该学生记录'}), 404
    d = dict(row)
    d['signed'] = bool(d['signature_img'] and d['signature_img'].strip())
    d['signed_at'] = str(d['signed_at']) if d['signed_at'] else None
    return jsonify(d)


# ── 安全告知书相关 API ──

@app.route('/api/safety_notice')
@login_required
def get_safety_notice():
    """获取当前安全告知书内容和模板列表"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'safety_notice'")
    row = cursor.fetchone()
    cursor.execute("SELECT value FROM settings WHERE key = 'safety_notice_template'")
    tmpl_row = cursor.fetchone()
    return jsonify({
        'html': (row['value'] if row else ''),
        'template': (tmpl_row['value'] if tmpl_row else 'winter'),
        'templates': {k: {'name': v['name'], 'icon': v['icon']} for k, v in SAFETY_NOTICE_TEMPLATES.items()},
    })


@app.route('/api/safety_notice_template/<template_key>')
@login_required
def get_safety_notice_template(template_key):
    """获取指定模板的渲染 HTML"""
    tmpl = SAFETY_NOTICE_TEMPLATES.get(template_key)
    if not tmpl:
        return jsonify({'error': '模板不存在'}), 404
    return jsonify({
        'html': render_safety_notice_html(tmpl),
        'template': template_key,
        'meta': {'name': tmpl['name'], 'icon': tmpl['icon']},
    })


@app.route('/admin/safety_notice', methods=['POST'])
@login_required
def save_safety_notice():
    """保存安全告知书内容"""
    data = request.json
    if not data:
        data = request.form
    html = (data.get('html') or data.get('safety_notice') or '').strip()
    template_key = (data.get('template') or data.get('safety_notice_template') or 'custom').strip()

    if not html:
        flash('安全告知书内容不能为空', 'error')
        return jsonify({'error': '内容不能为空'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ('safety_notice', html))
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ('safety_notice_template', template_key))
    db.commit()
    return jsonify({'success': True, 'message': '安全告知书已保存'})


@app.route('/api/optimize_safety_notice', methods=['POST'])
@login_required
def optimize_safety_notice():
    """AI 优化安全告知书"""
    data = request.json or {}
    season = data.get('season', '寒假')
    current_text = data.get('current_text', '')

    db = get_db()
    ai_config = get_ai_config(db)
    if not ai_config:
        return jsonify({'error': '请先在管理页面配置 AI 接口密钥'}), 400

    result, error = generate_safety_notice(ai_config, season, current_text)
    if error:
        return jsonify({'error': error}), 500

    return jsonify({'success': True, 'text': result})


@app.route('/api/publish', methods=['POST'])
@login_required
def publish_reports():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, student_name FROM student_reports WHERE status = 'draft'")
    drafts = cursor.fetchall()
    if not drafts:
        return jsonify({'error': '没有待发布的学生记录。'}), 400

    # Validate that all drafts have remarks
    cursor.execute("SELECT COUNT(*) as cnt FROM student_reports WHERE status = 'draft' AND (final_remarks IS NULL OR final_remarks = '')")
    missing = cursor.fetchone()['cnt']
    if missing > 0:
        return jsonify({'error': f'还有 {missing} 名学生没有填写评语，请完成后再发布。'}), 400

    for draft in drafts:
        cursor.execute(
            "DELETE FROM student_reports WHERE student_name = ? AND status = 'published'",
            (draft['student_name'],)
        )

    cursor.execute("UPDATE student_reports SET status = 'published' WHERE status = 'draft'")
    db.commit()
    flash(f'成功发布 {len(drafts)} 条学生记录！家长现在可以查询了。', 'success')
    return jsonify({'success': True, 'count': len(drafts)})


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', '0') == '1')

import os
import sqlite3
import pandas as pd
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, g) # Added g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # 在生产环境中替换为固定的强密钥
app.config['DATABASE'] = os.path.join(app.instance_path, 'school_data.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls'}

# --- Default Admin Credentials (for initial setup) ---
# 这些凭据仅用于首次创建管理员账户，之后登录将通过数据库验证
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "yourStrongPassword123!" # 请务必修改这个密码！

# Ensure instance and upload folders exist
try:
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except OSError as e:
    print(f"Error creating directories: {e}")
    pass # Or handle more gracefully

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

def init_db(app_context=None): # Allow passing app_context for CLI
    """Initializes the database and creates tables including a default admin."""
    def execute_init(db):
        cursor = db.cursor()
        # Create student_reports table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS student_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            chinese_score REAL,
            math_score REAL,
            english_score REAL,
            final_remarks TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        print("'student_reports' table created or already exists.")

        # Create admins table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        print("'admins' table created or already exists.")

        # Insert default admin user if not exists
        cursor.execute("SELECT id FROM admins WHERE username = ?", (DEFAULT_ADMIN_USERNAME,))
        if cursor.fetchone() is None:
            hashed_password = generate_password_hash(DEFAULT_ADMIN_PASSWORD, method='pbkdf2:sha256')
            cursor.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (DEFAULT_ADMIN_USERNAME, hashed_password)
            )
            print(f"Default admin user '{DEFAULT_ADMIN_USERNAME}' created.")
        else:
            print(f"Default admin user '{DEFAULT_ADMIN_USERNAME}' already exists.")
        
        db.commit()

    if app_context:
        with app_context:
            db = get_db()
            execute_init(db)
    else: # For direct call if app context isn't available (like initial setup check)
        with app.app_context():
            db = get_db()
            execute_init(db)
    print("Database initialization complete.")


# --- Initialize DB if it doesn't exist ---
# This is a simple way for development. For production, use a CLI command.
if not os.path.exists(app.config['DATABASE']):
    print(f"Database not found at {app.config['DATABASE']}. Initializing...")
    init_db(app_context=app.app_context()) # Pass the app context
else:
    print(f"Database found at {app.config['DATABASE']}.")

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

# --- Report Card Preamble (Hardcoded for now) ---
DEFAULT_ANNOUNCEMENT_HTML = """
<p><strong id="report-student-name-salutation" class="theme-purple-text">{student_name}</strong> 同学之家长：</p>
<p>您好！</p>
<p>
    在您的大力支持和配合下，本学期各项工作已顺利完成。根据教育局通知，我校暑假定于：<span class="double-underline font-semibold">2024年7月6日正式放假</span>，下学期<span class="double-underline font-semibold">2024年8月30日-8月31日开学报到，9月1日正式开学上课</span>。（此部分内容未来可由管理员在后台编辑更新）
</p>
<p>现将本学期贵子女的在校情况及相关事宜通知如下，请家长配合做好孩子在假期间的教育工作。</p>
"""
CURRENT_TERM_INFO = "2024-2025学年 第一学期"

# --- Routes ---
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
    cursor.execute("SELECT * FROM student_reports WHERE student_name = ? ORDER BY uploaded_at DESC LIMIT 1",
                   (student_name_query,))
    report = cursor.fetchone()

    if report:
        report_data = dict(report)
        report_data['announcement_html'] = DEFAULT_ANNOUNCEMENT_HTML.format(student_name=report_data['student_name'])
        report_data['term'] = CURRENT_TERM_INFO
        return jsonify(report_data)
    else:
        return jsonify({'error': f'未找到姓名为 "{student_name_query}" 的学生成绩信息。'}), 404


@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    return redirect(url_for('admin_upload_page'))

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


@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def admin_upload_page():
    if request.method == 'POST':
        if 'excel_file' not in request.files:
            flash('未检测到文件部分。', 'error')
            return redirect(request.url)
        file = request.files['excel_file']
        if file.filename == '':
            flash('未选择任何文件。', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # It's better to use a temporary file or a unique name to avoid conflicts
            # For simplicity, we'll overwrite if same name, but consider unique names
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(filepath)
                df = pd.read_excel(filepath)

                required_conceptual_cols = ['姓名', '语文', '数学', '英语', '期末评语']
                actual_columns = [str(col).strip() for col in df.columns]

                # Basic check if all required columns are conceptually present
                # This doesn't guarantee they are correctly named, just that a column with that name exists.
                missing_cols = [req_col for req_col in required_conceptual_cols if req_col not in actual_columns]
                if missing_cols:
                    flash(f'Excel文件表头缺少以下必需的列: {", ".join(missing_cols)}。检测到的列: {actual_columns}', 'error')
                    return redirect(request.url)

                db = get_db()
                cursor = db.cursor()
                records_processed = 0
                error_in_batch = False

                for index, row in df.iterrows():
                    try:
                        student_name = str(row['姓名']).strip()
                        if not student_name:
                            print(f"Skipping row {index+2} due to empty student name.")
                            continue
                        
                        # Delete old records for the same student
                        cursor.execute("DELETE FROM student_reports WHERE student_name = ?", (student_name,))

                        data_to_insert = {
                            'student_name': student_name,
                            'chinese_score': pd.to_numeric(row.get('语文'), errors='coerce'),
                            'math_score': pd.to_numeric(row.get('数学'), errors='coerce'),
                            'english_score': pd.to_numeric(row.get('英语'), errors='coerce'),
                            'final_remarks': str(row.get('期末评语', '')).strip() if pd.notna(row.get('期末评语')) else None
                        }
                        
                        for key, value in data_to_insert.items():
                            if pd.isna(value): # Check for pandas NaN or NaT
                                data_to_insert[key] = None
                        
                        cursor.execute("""
                            INSERT INTO student_reports (student_name, chinese_score, math_score, english_score, final_remarks)
                            VALUES (:student_name, :chinese_score, :math_score, :english_score, :final_remarks)
                        """, data_to_insert)
                        records_processed += 1
                    except KeyError as e:
                        flash(f'处理Excel第 {index+2} 行时出错: 表头可能不匹配，缺少列 "{e}"。请检查Excel文件。', 'error')
                        error_in_batch = True; break
                    except Exception as e:
                        flash(f'处理Excel第 {index+2} 行 ({row.get("姓名", "未知姓名")}) 时发生一般错误: {str(e)}', 'error')
                        error_in_batch = True; break
                
                if error_in_batch:
                    db.rollback()
                else:
                    db.commit()
                    flash(f'文件上传成功！共处理了 {records_processed} 条学生记录。', 'success')

            except pd.errors.EmptyDataError:
                flash('上传的Excel文件为空或格式无法识别。', 'error')
            except Exception as e:
                flash(f'处理文件时发生未知错误: {str(e)}', 'error')
                if 'db' in locals() and db and not error_in_batch: # Avoid rollback if already rolled back
                    db.rollback()
            finally:
                if 'filepath' in locals() and os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except OSError as e_remove:
                        print(f"Error removing temp file {filepath}: {e_remove}")
            return redirect(url_for('admin_upload_page'))
        else:
            flash('文件类型不被允许。请上传 .xlsx 或 .xls 文件。', 'error')
            return redirect(request.url)

    return render_template('admin_upload.html')


# --- Optional: CLI command to initialize DB ---
import click

@app.cli.command('init-db')
def init_db_command():
    """Clears existing data and creates new tables, including a default admin."""
    # You might want to ask for confirmation before clearing data in a real app
    db_path = app.config['DATABASE']
    if os.path.exists(db_path):
        print(f"Existing database found at {db_path}. It will be re-initialized.")
        # os.remove(db_path) # Optionally remove to start fresh; init_db handles IF NOT EXISTS
    
    init_db(app_context=app.app_context()) # Pass Flask app context
    print('Database initialized with default admin.')


if __name__ == '__main__':
    app.run(debug=True)
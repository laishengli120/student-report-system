#!/usr/bin/env python3
"""初始化测试数据库 - 包含有签名和无签名的学生记录

用法:
    python3 seed_test_data.py

如果 Pillow 未安装，将使用内置的极简 PNG 作为签名占位图。
"""
import sqlite3, os, sys, base64, io, random, datetime, hashlib, struct, zlib

INSTANCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'school_data.db')

# --- 假签名生成 (优先 Pillow，回退内置 PNG) ---
_HAS_PIL = False
try:
    from PIL import Image, ImageDraw
    _HAS_PIL = True
except ImportError:
    pass

def make_fake_signature(name):
    """生成签名图片的 base64 data URI"""
    if _HAS_PIL:
        return _make_sig_pil(name)
    else:
        return _make_sig_raw(name)

def _make_sig_pil(name):
    img = Image.new('RGBA', (400, 150), (255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    rng = random.Random(hash(name) % 10000)
    for _ in range(3):
        pts = []
        x = 30
        for i in range(60):
            y = 60 + int(30 * (i % 3)) + rng.randint(-8, 8)
            x = 20 + i * 6 + rng.randint(-2, 2)
            pts.append((x, y))
        draw.line(pts, fill=(30, 30, 30, 200), width=3)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()

def _make_sig_raw(name):
    """纯 Python 生成一个极简灰色 PNG（无 Pillow 回退）"""
    width, height = 200, 80
    # 生成 RGBA 像素数据
    raw_data = b''
    rng = random.Random(hash(name) % 10000)
    for y in range(height):
        raw_data += b'\x00'  # filter none
        for x in range(width):
            # 在中间画一条波浪线
            center_y = height // 2
            wave = int(12 * (rng.random() - 0.5))
            if abs(y - center_y - wave) < 4 and 30 < x < width - 30:
                dist = abs(y - center_y - wave)
                alpha = max(0, 220 - dist * 60)
                raw_data += bytes([40, 40, 40, alpha])
            else:
                raw_data += bytes([255, 255, 255, 0])

    def make_chunk(chunk_type, data):
        chunk = chunk_type + data
        return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)

    png = b'\x89PNG\r\n\x1a\n'
    png += make_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
    png += make_chunk(b'IDAT', zlib.compress(raw_data))
    png += make_chunk(b'IEND', b'')
    return 'data:image/png;base64,' + base64.b64encode(png).decode()

# 内联默认安全告知书 HTML（当 ai_service 不可用时使用）
SAFETY_NOTICE_DEFAULT_HTML = """                <div class="mb-6 border-2 border-paper-red rounded p-4 bg-red-50/20">
                    <div class="text-center mb-4">
                        <span class="bg-paper-red text-white px-6 py-1 rounded-full font-bold text-lg font-kaiti tracking-widest">假期安全告知书</span>
                    </div>

                    <p class="font-kaiti text-gray-800 mb-4 indent-8 leading-relaxed text-justify">
                        为了让孩子们度过一个平安、健康、愉快的假期，请各位家长切实承担起监护责任，与学校携手共同守护孩子的假期安全。在此，我们特别提醒您和孩子注意以下几个方面：
                    </p>

                    <div class="space-y-4 font-kaiti text-sm sm:text-base text-gray-700 leading-relaxed">
                        <div>
                            <span class="font-bold text-paper-red text-lg">❄️ 冬季防溺水：</span>
                            <span class="text-gray-800">冬季水面结冰，易发生溺水事故。请教育孩子不私自到河边、湖边滑冰、玩耍，并做到"四知道"——知道孩子去哪里、和谁去、做什么、何时回。</span>
                        </div>
                        <div>
                            <span class="font-bold text-paper-red text-lg">🔥 居家与消防安全：</span>
                            <span class="text-gray-800"><ol class="list-decimal list-inside ml-2 mt-1 space-y-1 text-gray-700 bg-white p-3 rounded border border-red-100"><li>注意用火用电用气安全，定期检查家中电器、燃气管道，做到人走火熄、电断、气关，取暖设备远离易燃物，切勿超负荷用电。</li><li>严禁在楼梯间、疏散通道等公共区域停放电动车或充电，切勿将电池带回家中充电。</li><li>自觉遵守禁放规定，不购买、不燃放烟花爆竹，不携带烟花爆竹进入公共场所，并主动劝阻家人和亲友的燃放行为。</li></ol></span>
                        </div>
                        <div>
                            <span class="font-bold text-paper-red">🚦 交通安全：</span>
                            遵守交通规则，过马路走斑马线，不闯红灯，不翻越护栏。未满12周岁不骑自行车上路，未满16周岁不骑电动车。乘坐正规交通工具，佩戴安全头盔，注意铁路安全。
                        </div>
                        <div>
                            <span class="font-bold text-paper-red">🥗 食品安全：</span>
                            注意饮食卫生，食材要新鲜、煮熟，不食用"三无"食品。外出就餐选择证照齐全的餐馆，避免暴饮暴食。
                        </div>
                        <div>
                            <span class="font-bold text-paper-red">🌐 网络安全：</span>
                            控制孩子使用电子产品的时间，防范网络沉迷和电信诈骗。教育孩子不轻信陌生信息、不泄露个人信息、不随意转账，文明上网，谨防网络交友风险。
                        </div>
                        <div>
                            <span class="font-bold text-paper-red">🌪️ 极端天气安全：</span>
                            关注天气预报，遇雨雪、冰冻、大风等天气尽量减少外出。外出时注意防滑防摔，远离积雪广告牌、树木等危险区域。
                        </div>
                        <div>
                            <span class="font-bold text-paper-red">⚖️ 法治与行为安全：</span>
                            教育孩子遵纪守法，不进入不宜场所，不接触不良人员。关注孩子心理与行为变化，及时沟通引导，防范欺凌行为。
                        </div>
                        <div>
                            <span class="font-bold text-paper-red">🏠 家庭环境与榜样作用：</span>
                            家长应以身作则，营造积极健康的家庭氛围，不让孩子接触不良信息与场所，不纵容不良行为。
                        </div>
                    </div>
                </div>"""

def init_db():
    # 确保 instance 目录存在
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    # 如果旧数据库存在，先删除
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print(f'已删除旧数据库: {DB_PATH}')
        except Exception as e:
            print(f'删除失败: {e}')
            # 尝试写入新路径
            pass

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 创建表
    cur.executescript("""
        CREATE TABLE student_reports (
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
            signed_at TIMESTAMP,
            position TEXT,
            status TEXT DEFAULT 'published',
            ai_remarks TEXT,
            brief_description TEXT
        );

        CREATE TABLE admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)

    # 导入安全告知书模块（如果 openai 不可用则使用内联默认值）
    safety_notice_html = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ai_service import SAFETY_NOTICE_TEMPLATES, render_safety_notice_html
        safety_notice_html = render_safety_notice_html(SAFETY_NOTICE_TEMPLATES['winter'])
    except ImportError:
        pass

    if safety_notice_html is None:
        safety_notice_html = SAFETY_NOTICE_DEFAULT_HTML  # fallback defined below

    # 插入默认设置
    defaults = {
        'holiday_start': '2026年1月31日',
        'next_term_report': '2026年3月4日',
        'next_term_start': '2026年3月5日',
        'ai_api_key': '',
        'ai_base_url': 'https://api.deepseek.com',
        'ai_model': 'deepseek-v4-flash',
        'grade_rules': '90=A\n80=B\n60=C\n0=D',
        'safety_notice': safety_notice_html,
        'safety_notice_template': 'winter',
    }
    for k, v in defaults.items():
        cur.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, v))

    # 插入默认管理员 (密码: admin123)
    salt = os.urandom(8).hex()
    dk = hashlib.pbkdf2_hmac('sha256', b'admin123', salt.encode(), 260000)
    hashed = f'pbkdf2:sha256:260000${salt}${dk.hex()}'
    cur.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ('admin', hashed))

    # 学生测试数据
    students = [
        ('黄梦芊', None,       96, 93, 97, 95, 91, '你是一个品学兼优的好学生，学习态度端正，成绩优异。希望继续保持，下学期更上一层楼！', True),
        ('张三',   '班长',       88, 92, 85, 90, 88, '作为班长，你认真负责，是老师的好帮手。学习上还需更加细心，争取各科齐头并进。', True),
        ('李四',   None,        72, 68, 75, 70, 73, '本学期学习态度有所改善，但成绩仍有提升空间。假期请加强基础巩固。', False),
        ('王五',   '学习委员',   94, 96, 91, 93, 95, '你聪慧好学，各方面表现突出。担任学习委员期间带领同学们共同进步。', True),
        ('赵六',   '劳动委员',   65, 72, 60, 68, 70, '你在劳动方面积极肯干，是同学们的好榜样。学习上需要更加努力。', False),
        ('陈小红', '文艺委员',   90, 85, 92, 87, 89, '多才多艺的你为班级带来许多欢乐。学业上稳中有进，继续保持！', True),
        ('刘小刚', None,        55, 62, 48, 58, 60, '本学期成绩不太理想，上课注意力不够集中。假期要多练多思，迎头赶上。', False),
        ('周小芳', '纪律委员',   87, 90, 88, 84, 86, '自律性强，遵守纪律，是同学们学习的榜样。希望下学期更大胆地表达自己的想法。', True),
        ('吴明',   '体育委员',   78, 80, 76, 82, 79, '体育场上你是健将，学习上也不甘落后。注意平衡好运动和学习的时间。', False),
    ]

    base_time = datetime.datetime(2026, 1, 28, 10, 0, 0)
    rng = random.Random(42)

    for i, (name, pos, cn, ma, en, sc, mo, remark, signed) in enumerate(students):
        sig_img = None
        sig_time = None
        if signed:
            sig_img = make_fake_signature(name)
            offset = datetime.timedelta(hours=rng.randint(1, 48), minutes=rng.randint(0, 59))
            sig_time = (base_time + offset).strftime('%Y-%m-%d %H:%M:%S')

        cur.execute("""
            INSERT INTO student_reports
                (student_name, position, chinese_score, math_score, english_score,
                 science_score, morality_score, final_remarks, status,
                 signature_img, signed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name, pos, cn, ma, en, sc, mo, remark, 'published', sig_img, sig_time
        ))
        status_icon = '✓ 已签' if signed else '✗ 未签'
        print(f'  [{status_icon}] {name} ({pos or "无职位"})')

    conn.commit()

    # 验证
    cur.execute('SELECT count(*) as cnt FROM student_reports')
    total = cur.fetchone()['cnt']
    cur.execute('SELECT count(*) as cnt FROM student_reports WHERE signature_img IS NOT NULL')
    signed = cur.fetchone()['cnt']
    print(f'\n总计 {total} 条学生记录，其中 {signed} 条已签收，{total - signed} 条未签收')
    conn.close()
    print('测试数据初始化完成!')

if __name__ == '__main__':
    init_db()

import time
from openai import OpenAI, RateLimitError, APIConnectionError, APITimeoutError, APIStatusError

TYPE_OPTIONS = [
    '优秀全能型', '乖巧可爱型', '淳朴大气型', '文静温和型',
    '口齿伶俐型', '默默无闻型', '兴趣特长型', '阳光温暖型',
    '勤奋自觉型', '正气有礼型', '聪明欠努力型', '贪玩好动型',
]

SYSTEM_PROMPT = """你是一位教龄二十年的小学班主任，正在给学生写期末评语。

核心原则：
- 以班主任视角关注学生的身心发展、性格品行、习惯养成，不要盯着成绩不放
- 涉及学习表现时一句话带过即可，切忌大段描述分数高低
- 以"你"开头，语气亲切温暖，像在和学生面对面聊天
- 先肯定学生的品性闪光点，再温和点出成长方向
- 结尾有新学期展望，表达信心与期待
- 字数60-90字，紧凑有温度，不说空话套话，宁短勿长

参考风格：

优秀全能型：
你是个全面发展的好孩子，做事认真有担当，同学们都信服你。新的学期，希望你在努力提升自己的同时，伸出友谊之手，带动身边的小伙伴一起进步！

乖巧可爱型：
你是位乖巧可爱的女孩，课堂上那双明亮的眼睛总是专注地看着老师。新的学期，希望你能更自信地亮出自己，站到舞台正中央！

淳朴大气型：
你年龄虽小，却淳朴中透着一份大气。生活中你勤劳积极，学习上你专注投入，清脆的发言声让人印象深刻。愿你一直执着上进，鲜花和掌声属于你。

文静温和型：
你言语不多，秀气温和，良好的习惯和品行首屈一指。新的学期，老师希望你能像小兔子一样蹦跳起来，让文静的你更添几分朝气。

口齿伶俐型：
你口齿伶俐、思维敏捷，是晨读领诵的明星。你活泼开朗、彬彬有礼，是大家心目中的文明小天使。新的学期，希望你继续做好表率！

默默无闻型：
你总是安静自觉地做好每一件事，不争不抢的样子让人欣慰。新的学期，希望你能大胆举手、积极发言，勇敢展示自己，会看到不一样的风景哦！

兴趣特长型：
你兴趣广泛，尤其痴迷乒乓球，那股坚持不懈的劲头让人佩服。新的学期，希望你戒骄戒躁，把这份韧劲带到每一件事上，不断超越自我。

阳光温暖型：
你像一颗小太阳，散发的光芒温暖着身边的每个人，能和你成为朋友是件多么幸福的事。新的学期，希望你继续发光发热，再创佳绩。

勤奋自觉型：
你积极进取，有恒心有耐心，自觉性很强。课堂上常能听到你响亮的回答，老师很欣赏你。新的学期，继续保持好状态，为明天奠基。

正气有礼型：
你有礼貌、知分寸，一身正气，素养无人能及。新的学期，希望你在提升综合素养的同时，锤炼意志，做个坚强勇敢的小小钢铁侠！

聪明欠努力型：
你是个聪明善良的孩子，尊敬老师，与同学和睦相处。你潜力很大，但对自己的要求还不够高。新的学期，加把劲，让自己更出色！

贪玩好动型：
你有礼貌、爱劳动、发言积极。但有时管不住自己，会贪玩调皮。新的学期，希望你把更多心思用在正事上，相信你会越来越棒！"""

USER_PROMPT_TEMPLATE = """请为{name}写一段期末评语。{position_info}该生属于{type_info}。学习情况参考：{score_info}。直接输出评语："""


def get_ai_config(db):
    cursor = db.cursor()
    cursor.execute(
        "SELECT key, value FROM settings WHERE key IN ('ai_api_key', 'ai_base_url', 'ai_model')"
    )
    rows = {row['key']: row['value'] for row in cursor.fetchall()}
    api_key = rows.get('ai_api_key', '').strip()
    if not api_key:
        return None
    return {
        'api_key': api_key,
        'base_url': rows.get('ai_base_url', 'https://api.deepseek.com').strip(),
        'model': rows.get('ai_model', 'deepseek-v4-flash').strip(),
    }


def _score_label(score):
    """将分数映射为定性标签，score 为 None 时返回 None"""
    if score is None:
        return None
    try:
        s = float(score)
    except (ValueError, TypeError):
        return None
    if s >= 90:
        return '优秀'
    elif s >= 75:
        return '良好'
    elif s >= 60:
        return '一般'
    else:
        return '薄弱'


def _build_messages(student_name, position, scores, types):
    pos = position.strip() if position else ''
    position_info = f'担任{pos}，' if pos else ''

    subjects = [
        ('语文', scores.get('语文')),
        ('数学', scores.get('数学')),
        ('英语', scores.get('英语')),
        ('科学', scores.get('科学')),
        ('道法', scores.get('道德与法治')),
    ]
    parts = []
    for subj, s in subjects:
        label = _score_label(s)
        if label:
            parts.append(f'{subj}{label}')
    score_info = '，'.join(parts) if parts else '暂无成绩数据'

    type_info = '、'.join(types) if types else '未指定（请结合成绩综合判断）'

    user_prompt = USER_PROMPT_TEMPLATE.format(
        name=student_name,
        position_info=position_info,
        score_info=score_info,
        type_info=type_info,
    )

    return [
        {'role': 'system', 'content': SYSTEM_PROMPT},
        {'role': 'user', 'content': user_prompt},
    ]


def _clean_comment(content, finish_reason):
    if content is None:
        return None, f'模型返回空内容（finish_reason={finish_reason}），请检查 API 密钥和模型名称是否正确'
    comment = content.strip()
    if not comment:
        return None, f'模型返回空白（finish_reason={finish_reason}），可尝试刷新重试'
    comment = comment.strip('"\' \n')
    for prefix in ['评语：', '评语:', '期末评语：', '期末评语:']:
        if comment.startswith(prefix):
            comment = comment[len(prefix):].strip()
    return comment, None


def generate_single_comment(student_name, position, scores, types, ai_config):
    if not ai_config or not ai_config.get('api_key'):
        return None, 'AI_API_KEY_NOT_CONFIGURED'

    messages = _build_messages(student_name, position, scores, types)
    last_error = None

    for attempt in range(3):
        try:
            client = OpenAI(
                api_key=ai_config['api_key'],
                base_url=ai_config['base_url'],
                timeout=90,
            )
            response = client.chat.completions.create(
                model=ai_config['model'],
                messages=messages,
                max_tokens=400,
                temperature=1.0,
                top_p=1.0,
                presence_penalty=0.3,
                extra_body={"thinking_mode": "non-thinking"},
            )

            choice = response.choices[0]
            return _clean_comment(choice.message.content, choice.finish_reason)

        except RateLimitError as e:
            last_error = f'API 请求过于频繁，请稍后重试（已重试 {attempt + 1} 次）'
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
        except (APIConnectionError, APITimeoutError) as e:
            last_error = f'无法连接 AI 服务（已重试 {attempt + 1} 次），请检查网络或 API 地址'
            if attempt < 2:
                time.sleep(1.5)
        except APIStatusError as e:
            if e.status_code >= 500:
                last_error = f'AI 服务暂时不可用（状态码 {e.status_code}，已重试 {attempt + 1} 次）'
                if attempt < 2:
                    time.sleep(2)
            else:
                return None, f'AI 接口返回错误（状态码 {e.status_code}）：{e.message}'
        except Exception as e:
            return None, f'AI 调用异常: {str(e)}'

    return None, last_error

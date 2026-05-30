import time
from openai import OpenAI, RateLimitError, APIConnectionError, APITimeoutError, APIStatusError

TYPE_OPTIONS = [
    '优秀全能型', '乖巧可爱型', '淳朴大气型', '文静温和型',
    '口齿伶俐型', '默默无闻型', '兴趣特长型', '阳光温暖型',
    '勤奋自觉型', '正气有礼型', '聪明欠努力型', '贪玩好动型',
]

SYSTEM_PROMPT = """你是一位教龄二十年的小学班主任，正在给学生写期末评语。

核心原则：
- 只关注学生的身心发展、性格品行、习惯养成，严禁提及任何成绩、分数、学习情况
- 不出现"成绩"、"分数"、"考试"、"学科"等与学业评价相关的词汇
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

USER_PROMPT_TEMPLATE = """请为{name}写一段期末评语。{position_info}该生属于{type_info}。直接输出评语："""


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


def _build_messages(student_name, position, types):
    pos = position.strip() if position else ''
    position_info = f'担任{pos}，' if pos else ''

    type_info = '、'.join(types) if types else '未指定（请选择学生类型标签）'

    user_prompt = USER_PROMPT_TEMPLATE.format(
        name=student_name,
        position_info=position_info,
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


def generate_single_comment(student_name, position, types, ai_config):
    if not ai_config or not ai_config.get('api_key'):
        return None, 'AI_API_KEY_NOT_CONFIGURED'

    messages = _build_messages(student_name, position, types)
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


# ── 安全告知书模板 ──

SAFETY_NOTICE_TEMPLATES = {
    'winter': {
        'name': '冬季寒假版',
        'icon': '❄️',
        'title': '假期安全告知书',
        'intro': '为了让孩子们度过一个平安、健康、愉快的假期，请各位家长切实承担起监护责任，与学校携手共同守护孩子的假期安全。在此，我们特别提醒您和孩子注意以下几个方面：',
        'sections': [
            {
                'title': '冬季防溺水',
                'icon': '❄️',
                'body': '冬季水面结冰，易发生溺水事故。请教育孩子不私自到河边、湖边滑冰、玩耍，并做到"四知道"——知道孩子去哪里、和谁去、做什么、何时回。',
            },
            {
                'title': '居家与消防安全',
                'icon': '🔥',
                'body': '<ol class="list-decimal list-inside ml-2 mt-1 space-y-1 text-gray-700 bg-white p-3 rounded border border-red-100"><li>注意用火用电用气安全，定期检查家中电器、燃气管道，做到人走火熄、电断、气关，取暖设备远离易燃物，切勿超负荷用电。</li><li>严禁在楼梯间、疏散通道等公共区域停放电动车或充电，切勿将电池带回家中充电。</li><li>自觉遵守禁放规定，不购买、不燃放烟花爆竹，不携带烟花爆竹进入公共场所，并主动劝阻家人和亲友的燃放行为。</li></ol>',
            },
            {
                'title': '交通安全',
                'icon': '🚦',
                'body': '遵守交通规则，过马路走斑马线，不闯红灯，不翻越护栏。未满12周岁不骑自行车上路，未满16周岁不骑电动车。乘坐正规交通工具，佩戴安全头盔，注意铁路安全。',
            },
            {
                'title': '食品安全',
                'icon': '🥗',
                'body': '注意饮食卫生，食材要新鲜、煮熟，不食用"三无"食品。外出就餐选择证照齐全的餐馆，避免暴饮暴食。',
            },
            {
                'title': '网络安全',
                'icon': '🌐',
                'body': '控制孩子使用电子产品的时间，防范网络沉迷和电信诈骗。教育孩子不轻信陌生信息、不泄露个人信息、不随意转账，文明上网，谨防网络交友风险。',
            },
            {
                'title': '极端天气安全',
                'icon': '🌪️',
                'body': '关注天气预报，遇雨雪、冰冻、大风等天气尽量减少外出。外出时注意防滑防摔，远离积雪广告牌、树木等危险区域。',
            },
            {
                'title': '法治与行为安全',
                'icon': '⚖️',
                'body': '教育孩子遵纪守法，不进入不宜场所，不接触不良人员。关注孩子心理与行为变化，及时沟通引导，防范欺凌行为。',
            },
            {
                'title': '家庭环境与榜样作用',
                'icon': '🏠',
                'body': '家长应以身作则，营造积极健康的家庭氛围，不让孩子接触不良信息与场所，不纵容不良行为。',
            },
        ],
    },
    'summer': {
        'name': '夏季暑假版',
        'icon': '☀️',
        'title': '假期安全告知书',
        'intro': '为了让孩子们度过一个平安、健康、愉快的暑假，请各位家长切实承担起监护责任，与学校携手共同守护孩子的假期安全。在此，我们特别提醒您和孩子注意以下几个方面：',
        'sections': [
            {
                'title': '防溺水安全',
                'icon': '🏊',
                'body': '夏季是溺水事故高发期，请务必教育孩子做到"六不"：不私自下水游泳，不擅自与他人结伴游泳，不在无家长带领的情况下游泳，不到无安全设施、无救援人员的水域游泳，不到不熟悉的水域游泳，不盲目下水施救。家长要做到"四知道"：知道孩子去哪里、和谁去、做什么、何时回。',
            },
            {
                'title': '防暑降温',
                'icon': '🌡️',
                'body': '高温天气尽量减少户外活动，避免在烈日下长时间暴晒。外出时做好防晒措施，多饮水，保持室内通风。如出现头晕、恶心等中暑症状，立即转移到阴凉处并补充水分，情况严重及时就医。',
            },
            {
                'title': '交通安全',
                'icon': '🚦',
                'body': '遵守交通规则，过马路走斑马线，不闯红灯，不翻越护栏。未满12周岁不骑自行车上路，未满16周岁不骑电动车。乘坐正规交通工具，佩戴安全头盔，不乘坐超载、无证车辆。',
            },
            {
                'title': '食品安全',
                'icon': '🥗',
                'body': '夏季气温高，食物易变质。注意饮食卫生，不食用过期、变质、"三无"食品，少吃生冷食物。外出就餐选择证照齐全的餐馆，避免暴饮暴食。',
            },
            {
                'title': '网络安全',
                'icon': '🌐',
                'body': '控制孩子使用电子产品的时间，防范网络沉迷和电信诈骗。教育孩子不轻信陌生信息、不泄露个人信息、不随意转账，文明上网，谨防网络交友风险。',
            },
            {
                'title': '防雷电安全',
                'icon': '⚡',
                'body': '夏季雷雨天气频繁，教育孩子雷雨天不在大树下、电线杆旁避雨，不使用手机等电子设备，关闭家中电器并拔掉电源插头。',
            },
            {
                'title': '法治与行为安全',
                'icon': '⚖️',
                'body': '教育孩子遵纪守法，不进入不宜场所，不接触不良人员。关注孩子心理与行为变化，及时沟通引导，防范欺凌行为。',
            },
            {
                'title': '家庭环境与榜样作用',
                'icon': '🏠',
                'body': '家长应以身作则，营造积极健康的家庭氛围，不让孩子接触不良信息与场所，不纵容不良行为。合理安排孩子作息，保证充足睡眠和适当锻炼。',
            },
        ],
    },
    'general': {
        'name': '通用版',
        'icon': '📋',
        'title': '假期安全告知书',
        'intro': '为了让孩子们度过一个平安、健康、愉快的假期，请各位家长切实承担起监护责任，与学校携手共同守护孩子的假期安全。在此，我们特别提醒您和孩子注意以下几个方面：',
        'sections': [
            {
                'title': '防溺水安全',
                'icon': '🏊',
                'body': '请教育孩子不私自到河边、池塘、水库等水域玩耍或游泳。家长要做到"四知道"：知道孩子去哪里、和谁去、做什么、何时回。',
            },
            {
                'title': '交通安全',
                'icon': '🚦',
                'body': '遵守交通规则，过马路走斑马线，不闯红灯，不翻越护栏。未满12周岁不骑自行车上路，未满16周岁不骑电动车。乘坐正规交通工具，佩戴安全头盔。',
            },
            {
                'title': '居家与消防安全',
                'icon': '🔥',
                'body': '注意用火用电用气安全，定期检查家中电器、燃气管道。取暖设备远离易燃物，切勿超负荷用电。严禁在楼梯间等公共区域停放电动车或充电。',
            },
            {
                'title': '食品安全',
                'icon': '🥗',
                'body': '注意饮食卫生，食材要新鲜、煮熟，不食用"三无"食品。外出就餐选择证照齐全的餐馆，避免暴饮暴食。',
            },
            {
                'title': '网络安全',
                'icon': '🌐',
                'body': '控制孩子使用电子产品的时间，防范网络沉迷和电信诈骗。教育孩子不轻信陌生信息、不泄露个人信息、不随意转账，文明上网。',
            },
            {
                'title': '法治与行为安全',
                'icon': '⚖️',
                'body': '教育孩子遵纪守法，不进入不宜场所，不接触不良人员。关注孩子心理与行为变化，及时沟通引导，防范欺凌行为。',
            },
            {
                'title': '家庭环境与榜样作用',
                'icon': '🏠',
                'body': '家长应以身作则，营造积极健康的家庭氛围，不让孩子接触不良信息与场所，不纵容不良行为。',
            },
        ],
    },
}


def render_safety_notice_html(template_data):
    """将模板数据渲染为 HTML 字符串"""
    sections_html = ''
    for sec in template_data.get('sections', []):
        icon = sec.get('icon', '')
        title = sec.get('title', '')
        body = sec.get('body', '')
        sections_html += f"""
                        <div>
                            <span class="font-bold text-paper-red text-lg">{icon} {title}：</span>
                            <span class="text-gray-800">{body}</span>
                        </div>"""

    return f"""                <div class="mb-6 border-2 border-paper-red rounded p-4 bg-red-50/20">
                    <div class="text-center mb-4">
                        <span class="bg-paper-red text-white px-6 py-1 rounded-full font-bold text-lg font-kaiti tracking-widest">{template_data.get('title', '假期安全告知书')}</span>
                    </div>

                    <p class="font-kaiti text-gray-800 mb-4 indent-8 leading-relaxed text-justify">
                        {template_data.get('intro', '')}
                    </p>

                    <div class="space-y-4 font-kaiti text-sm sm:text-base text-gray-700 leading-relaxed">
                        {sections_html}
                    </div>
                </div>"""


SAFETY_OPTIMIZE_PROMPT = """你是一位资深的小学德育主任，正在优化《假期安全告知书》。

要求：
1. 保持告知书正式、亲切、清晰，适合小学生家长阅读。
2. 如果用户只输入了安全主题或大点，例如“交通安全、食品安全、防溺水”，请把这些要点扩写成完整告知书，并补足必要的学校安全提醒。
3. 如果用户输入的是已有 HTML，请保留原有核心意思，优化语言和条目结构。
4. 覆盖用户明确输入的全部要点；必要时补充防溺水、交通、消防、食品、网络、极端天气、法治与行为、家庭环境等重点。
5. 如果季节信息明确（寒假/暑假），加入相应的季节性安全提示。
6. 开头引导段落 40-80 字，每个安全条目标题简洁，内容 1-2 句话。
7. 只输出可直接放入页面编辑框和预览区的 HTML 片段，不要输出 Markdown、代码块、解释说明或完整 html/body 标签。
8. HTML 结构请尽量使用下面这种形式，便于系统现有样式展示：

<div class="mb-6 border-2 border-paper-red rounded p-4 bg-red-50/20">
  <div class="text-center mb-4">
    <span class="bg-paper-red text-white px-6 py-1 rounded-full font-bold text-lg font-kaiti tracking-widest">假期安全告知书</span>
  </div>
  <p class="font-kaiti text-gray-800 mb-4 indent-8 leading-relaxed text-justify">引导段落</p>
  <div class="space-y-4 font-kaiti text-sm sm:text-base text-gray-700 leading-relaxed">
    <div><span class="font-bold text-paper-red text-lg">交通安全：</span><span class="text-gray-800">具体提醒。</span></div>
    <div><span class="font-bold text-paper-red text-lg">食品安全：</span><span class="text-gray-800">具体提醒。</span></div>
  </div>
</div>"""


def generate_safety_notice(ai_config, season='寒假', current_text=''):
    """AI 优化安全告知书"""
    if not ai_config or not ai_config.get('api_key'):
        return None, 'AI_API_KEY_NOT_CONFIGURED'

    prompt = SAFETY_OPTIMIZE_PROMPT
    if current_text:
        prompt += f'\n\n当前输入可能是 HTML、正文草稿，也可能只是安全主题要点。请据此优化或扩写：\n{current_text[:1200]}'
    else:
        prompt += f'\n\n请针对{season}生成一份全新的安全告知书。'

    last_error = None
    for attempt in range(2):
        try:
            client = OpenAI(
                api_key=ai_config['api_key'],
                base_url=ai_config['base_url'],
                timeout=90,
            )
            response = client.chat.completions.create(
                model=ai_config['model'],
                messages=[
                    {'role': 'system', 'content': prompt},
                    {'role': 'user', 'content': f'请生成{"优化并扩写" if current_text else "一份全新的"}《假期安全告知书》HTML（针对{season}）'}
                ],
                max_tokens=1800,
                temperature=0.8,
                extra_body={"thinking_mode": "non-thinking"},
            )
            content = response.choices[0].message.content
            if content:
                return content.strip(), None
            return None, '模型返回空内容'
        except RateLimitError:
            last_error = 'API 请求过于频繁，请稍后重试'
            if attempt < 1:
                time.sleep(2)
        except (APIConnectionError, APITimeoutError):
            last_error = '无法连接 AI 服务，请检查网络或 API 地址'
            if attempt < 1:
                time.sleep(1.5)
        except APIStatusError as e:
            return None, f'AI 接口返回错误（状态码 {e.status_code}）：{e.message}'
        except Exception as e:
            return None, f'AI 调用异常: {str(e)}'

    return None, last_error

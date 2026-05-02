# 期末通知书系统

## 简介
期末通知书自动生成系统，支持上传 Excel 学生信息、管理员登录认证、SQLite 数据存储，通过 AI 根据学生类型标签生成个性化期末评语，最终生成可签名确认的期末通知书（HTML 页面）。

## 功能特性
- **学生信息管理**：上传 Excel 表格，自动导入学生姓名、职位及各科成绩
- **AI 评语生成**：内置 12 种学生类型标签（优秀全能型、乖巧可爱型、勤奋自觉型等），AI 根据类型标签生成评语，不依赖成绩信息
- **评语审核工作流**：上传后进入草稿状态，支持逐条或批量生成 AI 评语，可手动修改后统一发布
- **家长查询页面**：家长输入学生姓名即可查看期末通知书，支持手写签名提交
- **时间参数配置**：后台可自定义寒暑假起止日期、下学期报到及开学时间
- **管理员认证**：基于 session 的登录认证，默认账号 admin / admin123

## 技术栈
- Python 3 / Flask
- SQLite（数据存储）
- Pandas（Excel 解析）
- OpenAI SDK（调用 DeepSeek 等兼容接口生成 AI 评语）
- Jinja2 + Tailwind CSS（前端页面渲染）

## 快速开始
```bash
# 安装依赖
pip install flask pandas openpyxl openai werkzeug

# 启动服务
python app.py
```

默认访问地址：`http://127.0.0.1:5000`

- 家长查询页：`/parent`
- 管理后台：`/admin/login`（默认账号 admin / admin123）

## AI 评语配置
在管理后台设置 AI 接口参数：
- API Key：你的 API 密钥
- Base URL：默认 `https://api.deepseek.com`
- Model：默认 `deepseek-v4-flash`

提示词已内置 12 种学生类型标签，AI 会聚焦于学生身心发展、性格品行和习惯养成，不涉及成绩评价。

## 项目结构
```
├── app.py              # Flask 主应用
├── ai_service.py       # AI 评语生成服务
├── requirements.txt    # Python 依赖
├── templates/          # HTML 模板
│   ├── admin_login.html
│   ├── admin_upload.html
│   ├── admin_review.html
│   └── parent_query.html
├── static/             # 静态资源
├── uploads/            # Excel 上传目录
└── instance/           # SQLite 数据库存储目录
```

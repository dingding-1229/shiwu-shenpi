# 事务审批系统

Flask + SQLite 的内部事务审批 Web 应用：注册登录、进食/花费申请、逐级审批、归档。国企公文风格 UI。

## 功能

- 首页注册 / 登录
- 进食申请（事项 + 进食时间）与花费申请（事项 + 金额）
- 指定多名审批人，按顺序逐级同意/驳回
- 办事台：我发起的 / 待我审批 / 已归档
- 文号格式：`事审[2026]xxx号`

## 本地运行

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

浏览器打开 `http://127.0.0.1:8000`。首次运行会自动创建 `data/app.db` 和 `secret.key`。

生产环境可用仓库中的 `ddmaxxing-oa.service` + `nginx-ddmaxxing-oa.conf` 作参考（gunicorn 反代）。

## 注意

不要把 `secret.key`、数据库或 API 密钥提交进仓库。

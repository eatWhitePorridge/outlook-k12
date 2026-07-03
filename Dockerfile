# gpt_register_lite —— 服务器 Docker 镜像
# 默认启动 FastAPI 服务常驻；配置走环境变量。

FROM python:3.12-slim

# 不写 pyc、日志实时 flush
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 先装依赖（利用层缓存）。构建上下文 = 项目目录 gpt_register_lite/
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 再拷代码：把整个包放到 /app/gpt_register_lite（保证 `python -m gpt_register_lite.api` 可用）
COPY . /app/gpt_register_lite/

# 非 root 运行 + token 缓存目录（可挂卷持久化，避免重启反复登录挤掉会话）
RUN useradd -m -u 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data
USER appuser

# token/DB/批量任务产物默认落到 /data（用 compose 挂卷持久化）
ENV CM_TOKEN_CACHE_PATH=/data/cm_token.json \
    PRODUCT_DIR=/data/product_files \
    REGISTER_DB_PATH=/data/register_console.db \
    BATCH_RUN_ROOT=/data/batch_runs \
    BATCH_PURGE_AFTER_UPLOAD=1 \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

# 健康检查打 /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/healthz').read()" || exit 1

# 默认：起 HTTP 服务。想跑 CLI 批量时 docker run 覆盖 command 即可：
#   docker run ... python -m gpt_register_lite.cli -c /dev/null -n 5 -o /data/results.json
CMD ["python", "-m", "gpt_register_lite.api"]

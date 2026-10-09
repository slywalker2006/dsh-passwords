FROM node:22.19.0-slim

WORKDIR /opt/dsh-passwords

RUN apt-get update \
  && apt-get install -y --no-install-recommends git python3 make g++ \
  && rm -rf /var/lib/apt/lists/*


COPY package.json npm-shrinkwrap.json tsconfig.json cordis.yml ./
RUN npm ci --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
COPY .env.example README.md README_en.md LICENSE ./
RUN npm run build

# 构建期版本断言：dsh-passwords 自身版本必须与 npm-shrinkwrap.json 锁定一致，
# 且构建产物 dist/cli.js --version 报告同一版本（update 引擎据此判定容器版本）。
RUN node -e "const fs=require('node:fs');const {execFileSync}=require('node:child_process');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));const lock=JSON.parse(fs.readFileSync('npm-shrinkwrap.json','utf8'));const cli=execFileSync(process.execPath,['./dist/cli.js','--version'],{encoding:'utf8'}).trim();if(pkg.version!==lock.version||pkg.version!==lock.packages[''].version||pkg.version!==cli){console.error('dsh-passwords version mismatch: pkg='+pkg.version+' lock='+lock.version+' cli='+cli);process.exit(1);}console.log('dsh-passwords '+pkg.version);"

COPY docker/docker-entrypoint.sh /usr/local/bin/dsh-passwords-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/dsh-passwords-entrypoint \
  && chmod 755 /usr/local/bin/dsh-passwords-entrypoint \
  && mkdir -p /data/dsh-passwords

ENV DSH_PASSWORDS_ENV_FILE=/data/dsh-passwords/.env
ENV DSH_PASSWORDS_RUNTIME=docker
ENV MCP_DB_PATH=/data/dsh-passwords/platform.db
ENV MCP_GATEWAY_AUTO_TLS=0
ENV MCP_GATEWAY_HOST=0.0.0.0
ENV MCP_GATEWAY_PORT=3088
ENV MCP_DSH_RESTART_SERVICE=

EXPOSE 3088
# 就绪探针：/gateway/readyz 在数据库不可用时返回 503，作为容器 health 依据（非存活探测）。
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.MCP_GATEWAY_PORT||'3088')+'/gateway/readyz').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["dsh-passwords-entrypoint"]
CMD ["node", "/opt/dsh-passwords/dist/cli.js", "serve-gateway"]

#!/usr/bin/env bash
# Apache Drill 1.22.0 + ZooKeeper 3.8.x (Ubuntu 22.04)
# Instalador "core" para o host do Drill (sem Nginx neste servidor).
# - Wizard interativo (ou variáveis via --vars)
# - Logs verbosos e arquivo de log
# - Arquivo de estado para retomar (--resume)
# - Systemd para ZooKeeper (tarball) e Drillbit
# - UI do Drill na 8047 (bind 0.0.0.0), JDBC/ODBC 31010
# - UFW opcional (libera 8047/31010 conforme redes informadas)
#
# Uso (interativo):
#   sudo ./install_drill_zk_ubuntu22.sh
#
# Uso (não-interativo com variáveis):
#   sudo ./install_drill_zk_ubuntu22.sh --vars /opt/vars.env --non-interactive
#
# Retomar da última etapa:
#   sudo ./install_drill_zk_ubuntu22.sh --resume --vars /opt/vars.env
#
set -euo pipefail

# =====================[ Variáveis padrão ]=====================
DRILL_VERSION_DEFAULT="1.22.0"
ZK_VERSION_DEFAULT="3.8.4"

# URLs com fallback (ajuste se preferir um mirror interno)
DRILL_TGZ_URL_DEFAULT="https://downloads.apache.org/drill/drill-${DRILL_VERSION_DEFAULT}/apache-drill-${DRILL_VERSION_DEFAULT}.tar.gz"
DRILL_TGZ_URL_FALLBACK_DEFAULT="https://archive.apache.org/dist/drill/drill-${DRILL_VERSION_DEFAULT}/apache-drill-${DRILL_VERSION_DEFAULT}.tar.gz"

ZK_TGZ_URL_DEFAULT="https://downloads.apache.org/zookeeper/zookeeper-${ZK_VERSION_DEFAULT}/apache-zookeeper-${ZK_VERSION_DEFAULT}-bin.tar.gz"
ZK_TGZ_URL_FALLBACK_DEFAULT="https://archive.apache.org/dist/zookeeper/zookeeper-${ZK_VERSION_DEFAULT}/apache-zookeeper-${ZK_VERSION_DEFAULT}-bin.tar.gz"

# Diretórios padrão
DRILL_PREFIX_DEFAULT="/opt/drill"
ZK_PREFIX_DEFAULT="/opt/zookeeper"
ZK_DATADIR_DEFAULT="/var/lib/zookeeper"

# Parâmetros de memória (ajuste conforme o host)
DRILL_HEAP_DEFAULT="4G"
DRILL_MAX_DIRECT_MEM_DEFAULT="8G"

# Rede / portas
DRILL_HTTP_PORT_DEFAULT="8047"
DRILL_USER_PORT_DEFAULT="31010"
ZK_PORT_DEFAULT="2181"

# Cluster e ZK
CLUSTER_ID_DEFAULT="DRILL_CLUSTER_PRINCIPAL"
ZK_CONNECT_DEFAULT="127.0.0.1:2181"
ZK_MYID_DEFAULT="1"

# Controles
DEFAULT_MANAGE_UFW="true"           # Se true, aplica regras no UFW conforme redes informadas
DEFAULT_WIPE_ZK_DATA="false"        # Se true, zera o dataDir do ZK (preserva myid)
DEFAULT_WIPE_ZK_CLUSTER="false"     # Se true, remove znode /drill/<cluster> antes de subir o Drill

# =====================[ Paths de log/estado ]==================
LOG_DIR="/var/log/drill-installer"
STATE_DIR="/var/lib/drill-installer"
CONF_DIR="/etc/drill-installer"
ANSWERS_FILE="${CONF_DIR}/answers.env"
STATE_FILE="${STATE_DIR}/state.env"
RUN_LOG="${LOG_DIR}/install-$(date +%F-%H%M%S).log"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"
exec > >(tee -a "$RUN_LOG") 2>&1

# Barra de progresso simples
progress() {
  local pct="$1"
  local w=50
  local filled=$((pct*w/100))
  printf "[PROGRESS] ["
  for ((i=0;i<filled;i++)); do printf "#"; done
  for ((i=filled;i<w;i++)); do printf "."; done
  printf "] %s%%\n" "$pct"
}

log(){ echo "[INFO]  $(date +%F\ %T) $*"; }
warn(){ echo "[WARN]  $(date +%F\ %T) $*" >&2; }
err(){ echo "[ERROR] $(date +%F\ %T) $*" >&2; }

save_state(){
  mkdir -p "$(dirname "$STATE_FILE")"
  echo "LAST_STEP=$1" > "$STATE_FILE"
}

load_state(){
  [[ -f "$STATE_FILE" ]] && source "$STATE_FILE" || true
}

# =====================[ Parse de argumentos ]==================
RESUME="false"
VARS_FILE=""
NON_INTERACTIVE="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resume) RESUME="true"; shift;;
    --vars) VARS_FILE="$2"; shift 2;;
    --non-interactive|-y) NON_INTERACTIVE="true"; shift;;
    *) err "Argumento desconhecido: $1"; exit 2;;
  esac
done

if [[ -n "$VARS_FILE" ]]; then
  if [[ -f "$VARS_FILE" ]]; then
    log "Carregando variáveis de $VARS_FILE"
    # shellcheck disable=SC1090
    source "$VARS_FILE"
  else
    err "--vars aponta para arquivo inexistente: $VARS_FILE"
    exit 2
  fi
fi

# =====================[ Funções auxiliares ]===================
need() {
  command -v "$1" >/dev/null 2>&1 || { err "Comando obrigatório não encontrado: $1"; exit 1; }
}

download_with_fallback(){
  local url="$1" fb="$2" dest="$3"
  if curl -fsSL "$url" -o "$dest"; then
    return 0
  else
    warn "Falha ao baixar de $url, tentando fallback..."
    curl -fsSL "$fb" -o "$dest"
  fi
}

ensure_user_group(){
  local u="$1" g="$2"
  if ! id -u "$u" >/dev/null 2>&1; then
    adduser --system --no-create-home --group "$u" || true
  fi
  getent group "$g" >/dev/null 2>&1 || groupadd "$g" || true
}

apply_ufw_rule(){
  local port="$1" proto="$2" src="$3" label="$4"
  if [[ "$MANAGE_UFW" == "true" && -n "$src" && "$src" != "none" ]]; then
    ufw allow proto "$proto" from "$src" to any port "$port" comment "$label" >/dev/null || true
  fi
}

# =====================[ Wizard ]===============================
wizard(){
  echo
  echo "=== Apache Drill — Instalador CORE (Ubuntu 22.04; ZK 3.8.x + Drill 1.22) ==="

  read -rp "Versão do Apache Drill [${DRILL_VERSION_DEFAULT}]: " DRILL_VERSION || true
  DRILL_VERSION="${DRILL_VERSION:-$DRILL_VERSION_DEFAULT}"

  read -rp "Versão do ZooKeeper [${ZK_VERSION_DEFAULT}]: " ZK_VERSION || true
  ZK_VERSION="${ZK_VERSION:-$ZK_VERSION_DEFAULT}"

  read -rp "ID do cluster Drill [${CLUSTER_ID_DEFAULT}]: " CLUSTER_ID || true
  CLUSTER_ID="${CLUSTER_ID:-$CLUSTER_ID_DEFAULT}"

  read -rp "ZooKeeper connect string [${ZK_CONNECT_DEFAULT}]: " ZK_CONNECT || true
  ZK_CONNECT="${ZK_CONNECT:-$ZK_CONNECT_DEFAULT}"

  read -rp "myid do ZooKeeper (1..255) [${ZK_MYID_DEFAULT}]: " ZK_MYID || true
  ZK_MYID="${ZK_MYID:-$ZK_MYID_DEFAULT}"

  read -rp "Porta Web (UI) do Drill [${DRILL_HTTP_PORT_DEFAULT}]: " DRILL_HTTP_PORT || true
  DRILL_HTTP_PORT="${DRILL_HTTP_PORT:-$DRILL_HTTP_PORT_DEFAULT}"

  read -rp "Porta User (JDBC/ODBC) [${DRILL_USER_PORT_DEFAULT}]: " DRILL_USER_PORT || true
  DRILL_USER_PORT="${DRILL_USER_PORT:-$DRILL_USER_PORT_DEFAULT}"

  read -rp "Tamanho DRILL_HEAP [${DRILL_HEAP_DEFAULT}]: " DRILL_HEAP || true
  DRILL_HEAP="${DRILL_HEAP:-$DRILL_HEAP_DEFAULT}"

  read -rp "Tamanho DRILL_MAX_DIRECT_MEMORY [${DRILL_MAX_DIRECT_MEM_DEFAULT}]: " DRILL_MAX_DIRECT_MEMORY || true
  DRILL_MAX_DIRECT_MEMORY="${DRILL_MAX_DIRECT_MEMORY:-$DRILL_MAX_DIRECT_MEM_DEFAULT}"

  read -rp "Rede/CIDR do(s) proxy(s) Nginx que podem acessar a UI ${DRILL_HTTP_PORT} (ex: 10.0.0.0/8) [none]: " UI_ALLOWED || true
  UI_ALLOWED="${UI_ALLOWED:-none}"

  read -rp "Rede/CIDR autorizada para 31010 (JDBC/ODBC) [none]: " JDBC_ALLOWED || true
  JDBC_ALLOWED="${JDBC_ALLOWED:-none}"

  read -rp "Aplicar regras UFW automaticamente? (y/N) " ans || true
  MANAGE_UFW=$([[ "${ans:-N}" =~ ^[Yy]$ ]] && echo "true" || echo "false")

  read -rp "Zerar dataDir do ZK (limpo) se detectar estado antigo? (y/N) " ans2 || true
  WIPE_ZK_DATA=$([[ "${ans2:-N}" =~ ^[Yy]$ ]] && echo "true" || echo "false")

  read -rp "Remover znode /drill/${CLUSTER_ID} antes de subir (WIPE_ZK_CLUSTER)? (y/N) " ans3 || true
  WIPE_ZK_CLUSTER=$([[ "${ans3:-N}" =~ ^[Yy]$ ]] && echo "true" || echo "false")

  # Construir URLs a partir das versões
  DRILL_TGZ_URL="https://downloads.apache.org/drill/drill-${DRILL_VERSION}/apache-drill-${DRILL_VERSION}.tar.gz"
  DRILL_TGZ_URL_FALLBACK="https://archive.apache.org/dist/drill/drill-${DRILL_VERSION}/apache-drill-${DRILL_VERSION}.tar.gz"
  ZK_TGZ_URL="https://downloads.apache.org/zookeeper/zookeeper-${ZK_VERSION}/apache-zookeeper-${ZK_VERSION}-bin.tar.gz"
  ZK_TGZ_URL_FALLBACK="https://archive.apache.org/dist/zookeeper/zookeeper-${ZK_VERSION}/apache-zookeeper-${ZK_VERSION}-bin.tar.gz"

  mkdir -p "$(dirname "$ANSWERS_FILE")"
  cat > "$ANSWERS_FILE" <<EOF
DRILL_VERSION="$DRILL_VERSION"
ZK_VERSION="$ZK_VERSION"
CLUSTER_ID="$CLUSTER_ID"
ZK_CONNECT="$ZK_CONNECT"
ZK_MYID="$ZK_MYID"
DRILL_HTTP_PORT="$DRILL_HTTP_PORT"
DRILL_USER_PORT="$DRILL_USER_PORT"
DRILL_HEAP="$DRILL_HEAP"
DRILL_MAX_DIRECT_MEMORY="$DRILL_MAX_DIRECT_MEMORY"
UI_ALLOWED="$UI_ALLOWED"
JDBC_ALLOWED="$JDBC_ALLOWED"
MANAGE_UFW="$MANAGE_UFW"
WIPE_ZK_DATA="$WIPE_ZK_DATA"
WIPE_ZK_CLUSTER="$WIPE_ZK_CLUSTER"
DRILL_TGZ_URL="$DRILL_TGZ_URL"
DRILL_TGZ_URL_FALLBACK="$DRILL_TGZ_URL_FALLBACK"
ZK_TGZ_URL="$ZK_TGZ_URL"
ZK_TGZ_URL_FALLBACK="$ZK_TGZ_URL_FALLBACK"
DRILL_PREFIX="${DRILL_PREFIX_DEFAULT}"
ZK_PREFIX="${ZK_PREFIX_DEFAULT}"
ZK_DATADIR="${ZK_DATADIR_DEFAULT}"
EOF
  log "Wizard concluído. Respostas em $ANSWERS_FILE"
}

load_answers_or_defaults(){
  # Carrega respostas do wizard ou usa defaults/variáveis existentes
  if [[ -f "$ANSWERS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ANSWERS_FILE"
  fi

  DRILL_VERSION="${DRILL_VERSION:-$DRILL_VERSION_DEFAULT}"
  ZK_VERSION="${ZK_VERSION:-$ZK_VERSION_DEFAULT}"
  CLUSTER_ID="${CLUSTER_ID:-$CLUSTER_ID_DEFAULT}"
  ZK_CONNECT="${ZK_CONNECT:-$ZK_CONNECT_DEFAULT}"
  ZK_MYID="${ZK_MYID:-$ZK_MYID_DEFAULT}"
  DRILL_HTTP_PORT="${DRILL_HTTP_PORT:-$DRILL_HTTP_PORT_DEFAULT}"
  DRILL_USER_PORT="${DRILL_USER_PORT:-$DRILL_USER_PORT_DEFAULT}"
  DRILL_HEAP="${DRILL_HEAP:-$DRILL_HEAP_DEFAULT}"
  DRILL_MAX_DIRECT_MEMORY="${DRILL_MAX_DIRECT_MEMORY:-$DRILL_MAX_DIRECT_MEM_DEFAULT}"
  UI_ALLOWED="${UI_ALLOWED:-none}"
  JDBC_ALLOWED="${JDBC_ALLOWED:-none}"
  MANAGE_UFW="${MANAGE_UFW:-$DEFAULT_MANAGE_UFW}"
  WIPE_ZK_DATA="${WIPE_ZK_DATA:-$DEFAULT_WIPE_ZK_DATA}"
  WIPE_ZK_CLUSTER="${WIPE_ZK_CLUSTER:-$DEFAULT_WIPE_ZK_CLUSTER}"
  DRILL_TGZ_URL="${DRILL_TGZ_URL:-$DRILL_TGZ_URL_DEFAULT}"
  DRILL_TGZ_URL_FALLBACK="${DRILL_TGZ_URL_FALLBACK:-$DRILL_TGZ_URL_FALLBACK_DEFAULT}"
  ZK_TGZ_URL="${ZK_TGZ_URL:-$ZK_TGZ_URL_DEFAULT}"
  ZK_TGZ_URL_FALLBACK="${ZK_TGZ_URL_FALLBACK:-$ZK_TGZ_URL_FALLBACK_DEFAULT}"
  DRILL_PREFIX="${DRILL_PREFIX:-$DRILL_PREFIX_DEFAULT}"
  ZK_PREFIX="${ZK_PREFIX:-$ZK_PREFIX_DEFAULT}"
  ZK_DATADIR="${ZK_DATADIR:-$ZK_DATADIR_DEFAULT}"

  DRILL_ROOT="${DRILL_PREFIX}/current"
}

# =====================[ Pré-checagens ]========================
need curl
need tar
need ss
need nc

log "SO: $(lsb_release -sd 2>/dev/null || echo Ubuntu 22.04)"
log "Kernel: $(uname -r)  |  Arquitetura: $(uname -m)"
log "CPU(s): $(nproc)  |  Mem: $(LC_ALL=C free -h | awk '/Mem:/ {print $2}')  |  Disco livre /: $(df -hP / | awk 'NR==2{print $4}')"
progress 5

# =====================[ Wizard/variáveis ]=====================
if [[ "$NON_INTERACTIVE" == "false" && "$RESUME" == "false" ]]; then
  wizard
fi
load_answers_or_defaults

# =====================[ RESUME ]===============================
load_state
CURRENT_STEP="${LAST_STEP:-0}"

step_should_run(){
  local num="$1"
  [[ "$RESUME" == "false" ]] && return 0
  # roda se num > CURRENT_STEP
  [[ "$num" -gt "$CURRENT_STEP" ]]
}

# =====================[ Etapas ]===============================

# 1) Pacotes básicos
if step_should_run 1; then
  log "Instalando pacotes básicos (OpenJDK 11, UFW, etc.)…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openjdk-11-jdk curl wget gnupg lsb-release ca-certificates \
    netcat-openbsd iproute2 ufw
  save_state 1
  progress 15
fi

# 2) Desabilitar/mascar serviços ZK de pacote (se existirem)
if step_should_run 2; then
  if systemctl list-unit-files | grep -q '^zookeeper\.service'; then
    log "Desabilitando/mask zookeeper.service do pacote (evitar conflito)…"
    systemctl stop zookeeper || true
    systemctl disable zookeeper || true
    systemctl mask zookeeper || true
  fi
  save_state 2
  progress 20
fi

# 3) Instalar ZooKeeper (tarball) + systemd
if step_should_run 3; then
  log "Instalando ZooKeeper ${ZK_VERSION} (tarball) em ${ZK_PREFIX}…"
  mkdir -p "$ZK_PREFIX"
  TMP_ZK="/tmp/apache-zookeeper-${ZK_VERSION}-bin.tar.gz"
  download_with_fallback "$ZK_TGZ_URL" "$ZK_TGZ_URL_FALLBACK" "$TMP_ZK"
  tar -C /opt -xzf "$TMP_ZK"
  rm -f "$TMP_ZK"
  ln -sfn "/opt/apache-zookeeper-${ZK_VERSION}-bin" "$ZK_PREFIX"

  ensure_user_group zookeeper zookeeper
  mkdir -p "$ZK_DATADIR"
  chown -R zookeeper:zookeeper "$ZK_DATADIR"

  # zoo.cfg (standalone)
  cat > "${ZK_PREFIX}/conf/zoo.cfg" <<EOF
tickTime=2000
initLimit=10
syncLimit=5
dataDir=${ZK_DATADIR}
clientPort=${ZK_PORT_DEFAULT}
admin.enableServer=true
admin.serverPort=8080
4lw.commands.whitelist=ruok,stat,srvr,conf,mntr,wchp,wchc
autopurge.snapRetainCount=3
autopurge.purgeInterval=0
EOF

  # myid
  echo "${ZK_MYID}" > "${ZK_DATADIR}/myid"
  chown zookeeper:zookeeper "${ZK_DATADIR}/myid"

  # Opcional: limpar estado anterior
  if [[ "$WIPE_ZK_DATA" == "true" ]]; then
    log "Limpando estado antigo do ZK em ${ZK_DATADIR} (preservando myid)…"
    find "${ZK_DATADIR}" -maxdepth 1 -type f ! -name myid -delete || true
    rm -rf "${ZK_DATADIR}/version-2" || true
    mkdir -p "${ZK_DATADIR}/version-2"
    chown -R zookeeper:zookeeper "${ZK_DATADIR}"
  fi

  # systemd unit
  cat > /etc/systemd/system/zookeeper-bin.service <<'EOF'
[Unit]
Description=Apache ZooKeeper (tarball)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=zookeeper
Group=zookeeper
Environment=JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ExecStart=/opt/zookeeper/bin/zkServer.sh start-foreground
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable zookeeper-bin
  systemctl restart zookeeper-bin

  # Saúde do ZK
  sleep 1
  if ! echo ruok | nc -w2 127.0.0.1 "${ZK_PORT_DEFAULT}" | grep -q imok; then
    err "ZooKeeper não respondeu 'imok' em 127.0.0.1:${ZK_PORT_DEFAULT}"
    journalctl -u zookeeper-bin -n100 --no-pager
    exit 1
  fi
  save_state 3
  progress 45
fi

# 4) Instalar Apache Drill
if step_should_run 4; then
  log "Instalando Apache Drill ${DRILL_VERSION} em ${DRILL_PREFIX}…"
  mkdir -p "$DRILL_PREFIX"
  TMP_DRILL="/tmp/apache-drill-${DRILL_VERSION}.tar.gz"
  download_with_fallback "$DRILL_TGZ_URL" "$DRILL_TGZ_URL_FALLBACK" "$TMP_DRILL"
  tar -C /opt -xzf "$TMP_DRILL"
  rm -f "$TMP_DRILL"
  ln -sfn "/opt/apache-drill-${DRILL_VERSION}" "$DRILL_PREFIX/current"

  ensure_user_group drill drill
  chown -R drill:drill "/opt/apache-drill-${DRILL_VERSION}" "$DRILL_PREFIX" || true

  # drill-override.conf mínimo
  mkdir -p "${DRILL_ROOT}/conf"
  cat > "${DRILL_ROOT}/conf/drill-override.conf" <<EOF
drill.exec: {
  cluster-id: "${CLUSTER_ID}",
  zk.connect: "${ZK_CONNECT}",
  http: { enabled: true, port: ${DRILL_HTTP_PORT} },
  security.user.auth { enabled: false }
}
EOF
  chown -R drill:drill "${DRILL_ROOT}/conf"

  # systemd do Drillbit
  cat > /etc/systemd/system/drillbit.service <<'EOF'
[Unit]
Description=Apache Drillbit
After=network-online.target zookeeper-bin.service
Wants=network-online.target

[Service]
Type=simple
User=drill
Group=drill
# Memória (ajustável via EnvironmentOverride)
Environment=DRILL_HEAP=4G
Environment=DRILL_MAX_DIRECT_MEMORY=8G
# UI bind/porta (ajustável via drop-in)
Environment=DRILLBIT_JAVA_OPTS=-Ddrill.exec.http.enabled=true -Ddrill.exec.http.port=8047 -Ddrill.exec.http.bind_address=0.0.0.0
ExecStart=/opt/drill/current/bin/drillbit.sh run
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  # Ajusta os valores de memória e porta via drop-in
  mkdir -p /etc/systemd/system/drillbit.service.d
  cat > /etc/systemd/system/drillbit.service.d/override.conf <<EOF
[Service]
Environment=DRILL_HEAP=${DRILL_HEAP}
Environment=DRILL_MAX_DIRECT_MEMORY=${DRILL_MAX_DIRECT_MEMORY}
Environment=DRILLBIT_JAVA_OPTS=-Ddrill.exec.http.enabled=true -Ddrill.exec.http.port=${DRILL_HTTP_PORT} -Ddrill.exec.http.bind_address=0.0.0.0
EOF

  systemctl daemon-reload
  systemctl enable drillbit

  # Limpeza do znode /drill/<cluster> se solicitado
  if [[ "$WIPE_ZK_CLUSTER" == "true" ]]; then
    log "Removendo znode /drill/${CLUSTER_ID} no ZooKeeper (se existir)…"
    "${ZK_PREFIX}/bin/zkCli.sh" -server 127.0.0.1:${ZK_PORT_DEFAULT} <<EOF || true
ls /
ls /drill
rmr /drill/${CLUSTER_ID}
quit
EOF
  fi

  systemctl restart drillbit
  sleep 3

  # Checagem de portas
  if ! ss -lntp | egrep -q ":${DRILL_HTTP_PORT}\b|:${DRILL_USER_PORT}\b"; then
    warn "Portas do Drill ainda não visíveis, aguardando até 20s…"
    for i in {1..20}; do
      ss -lntp | egrep -q ":${DRILL_HTTP_PORT}\b|:${DRILL_USER_PORT}\b" && break
      sleep 1
    done
  fi

  ss -lntp | egrep -q ":${DRILL_HTTP_PORT}\b" || { journalctl -u drillbit -n150 --no-pager; err "Porta HTTP ${DRILL_HTTP_PORT} não abriu."; exit 1; }

  save_state 4
  progress 75
fi

# 5) UFW (opcional)
if step_should_run 5; then
  if [[ "$MANAGE_UFW" == "true" ]]; then
    log "Aplicando regras UFW…"
    ufw status | grep -q inactive && ufw --force enable || true

    # Permite 8047 a partir das redes informadas (ex: proxies Nginx)
    apply_ufw_rule "$DRILL_HTTP_PORT" tcp "$UI_ALLOWED" "drill-ui-${DRILL_HTTP_PORT}"

    # Permite 31010 (JDBC/ODBC) a partir de redes específicas
    apply_ufw_rule "$DRILL_USER_PORT" tcp "$JDBC_ALLOWED" "drill-user-${DRILL_USER_PORT}"

    # Sempre permite loopback local para debug
    ufw allow in on lo comment "loopback" >/dev/null || true
  else
    log "MANAGE_UFW=false — pulando configuração de firewall."
  fi
  save_state 5
  progress 85
fi

# 6) Validações finais
if step_should_run 6; then
  log "Validações finais…"
  echo "  - ZK ruok: $(echo ruok | nc -w2 127.0.0.1 ${ZK_PORT_DEFAULT} || true)"
  echo "  - Drill UI header: $(curl -sS -I http://127.0.0.1:${DRILL_HTTP_PORT}/ | head -n1 || true)"
  echo "  - Portas: "
  ss -lntp | egrep ":${ZK_PORT_DEFAULT}\b|:${DRILL_HTTP_PORT}\b|:${DRILL_USER_PORT}\b" || true
  save_state 6
  progress 100
fi

echo
log "Instalação concluída!"
echo "Resumo:"
echo "  Drill:         ${DRILL_VERSION}  (${DRILL_ROOT})"
echo "  Zookeeper:     ${ZK_VERSION}     (${ZK_PREFIX})"
echo "  Cluster ID:    ${CLUSTER_ID}"
echo "  ZK connect:    ${ZK_CONNECT}"
echo "  Drill UI:      http://<IP>:${DRILL_HTTP_PORT}  (bind 0.0.0.0)"
echo "  JDBC/ODBC:     ${DRILL_USER_PORT}"
echo "  UFW:           ${MANAGE_UFW}  | UI_ALLOWED=${UI_ALLOWED}  | JDBC_ALLOWED=${JDBC_ALLOWED}"
echo "  Estado:        ${STATE_FILE}"
echo "  Respostas:     ${ANSWERS_FILE}"
echo "  Log:           ${RUN_LOG}"

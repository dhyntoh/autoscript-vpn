#!/bin/bash
SCRIPT_DIR="/opt/autoscript-vpn"

case "$1" in
    start)
        systemctl start autoscript-manager autoscript-bot
        echo "✅ Services started"
        ;;
    stop)
        systemctl stop autoscript-manager autoscript-bot
        echo "⏹️ Services stopped"
        ;;
    restart)
        systemctl restart autoscript-manager autoscript-bot
        echo "🔄 Services restarted"
        ;;
    status)
        systemctl status autoscript-manager autoscript-bot
        ;;
    logs)
        tail -f $SCRIPT_DIR/logs/*.log
        ;;
    update)
        cd $SCRIPT_DIR
        git pull
        systemctl restart autoscript-manager autoscript-bot
        echo "✅ System updated"
        ;;
    backup)
        tar -czf /tmp/autoscript-backup-$(date +%Y%m%d).tar.gz $SCRIPT_DIR/data
        echo "📦 Backup created: /tmp/autoscript-backup-$(date +%Y%m%d).tar.gz"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|update|backup}"
        echo
        echo "Examples:"
        echo "  sudo ./manage.sh start    - Start services"
        echo "  sudo ./manage.sh logs     - View logs"
        echo "  sudo ./manage.sh backup   - Create backup"
        exit 1
        ;;
esac
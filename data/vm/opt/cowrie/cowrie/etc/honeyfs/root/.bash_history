sudo apt update
sudo apt install -y nginx php8.1-fpm mysql-client
cd /var/www/html
git pull origin main
sudo systemctl reload nginx
df -h

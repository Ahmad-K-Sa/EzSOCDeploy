# Installing NGINX
sudo apt update
sudo apt install -y nginx

sudo ufw allow 'Nginx HTTP'

sudo systemctl start nginx
sudo systemctl enable nginx

# configuring soc dashboard
sudo mkdir -p /var/www/soc-dashboard.com/html
sudo chown -R $USER:$USER /var/www/soc-dashboard.com/html

sudo chmod -R 755 /var/www/soc-dashboard.com

printf "server {\r\n    listen 80;\r\n\r\n    server_name soc-dashboard.com www.soc-dashboard.com;\r\n\r\n    auth_basic \"Restricted Access\";\r\n    auth_basic_user_file /etc/nginx/htpasswd.users;\r\n\r\n    location / {\r\n        proxy_pass http://localhost:5601;\r\n        proxy_http_version 1.1;\r\n        proxy_set_header Upgrade \$http_upgrade;\r\n        proxy_set_header Connection 'upgrade';\r\n        proxy_set_header Host \$host;\r\n        proxy_cache_bypass \$http_upgrade;\r\n    }\r\n}\r\n" > /etc/nginx/sites-available/soc-dashboard.com

sudo ln -s /etc/nginx/sites-available/soc-dashboard.com /etc/nginx/sites-enabled/

sudo bash -c 'printf "user www-data;\r\nworker_processes auto;\r\npid /run/nginx.pid;\r\ninclude /etc/nginx/modules-enabled/*.conf;\r\nevents {\r\n\tworker_connections 768;\r\n}\r\nhttp {\r\n\tsendfile on;\r\n\ttcp_nopush on;\r\n\ttypes_hash_max_size 2048;\r\n\tserver_names_hash_bucket_size 64;\r\n\tinclude /etc/nginx/mime.types;\r\n\tdefault_type application/octet-stream;\r\n\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; \r\n\tssl_prefer_server_ciphers on;\r\n\taccess_log /var/log/nginx/access.log;\r\n\terror_log /var/log/nginx/error.log;\r\n\tgzip on;\r\n\tinclude /etc/nginx/conf.d/*.conf;\r\n\tinclude /etc/nginx/sites-enabled/*;\r\n}" > /etc/nginx/nginx.conf'

sudo apt install -y curl
# Restarting NGINX for dashboard to load
sudo systemctl restart nginx

# Installing Elasrticsearch
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch |sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install -y elasticsearch

#Making Elasticsearch accessible only by localhost
echo "network.host: localhost" >> /etc/elasticsearch/elasticsearch.yml

# Starting the service and enabling it on startup
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# Installing Kibana 
sudo apt install -y kibana

# Starting the service and enabling it on startup
sudo systemctl enable kibana
sudo systemctl start kibana

# NGINX Kibana admin login creds
# echo "enter kibanadmin password"
# echo "kibanaadmin:`openssl passwd -apr1`" | sudo tee -a /etc/nginx/htpasswd.users

# use above commented lines to enter password manually, bellow inserts the user kibanaadmin with password azerty
printf "kibanaadmin:\$apr1\$ldZ2at99\$qAkvvyLqOMH1MS4g6ryKy." > /etc/nginx/htpasswd.users

# Installing Logstash
sudo apt install -y logstash

# adding config files
printf "input {\r\n  beats {\r\n    port => 5044\r\n  }\r\n}" >/etc/logstash/conf.d/02-beats-input.conf

printf "output {\r\n  if [@metadata][pipeline] {\r\n\telasticsearch {\r\n  \thosts => [\"localhost:9200\"]\r\n  \tmanage_template => false\r\n  \tindex => \"%%{[@metadata][beat]}-%%{[@metadata][version]}-%%{+YYYY.MM.dd}\"\r\n  \tpipeline => \"%%{[@metadata][pipeline]}\"\r\n\t}\r\n  } else {\r\n\telasticsearch {\r\n  \thosts => [\"localhost:9200\"]\r\n  \tmanage_template => false\r\n  \tindex => \"%%{[@metadata][beat]}-%%{[@metadata][version]}-%%{+YYYY.MM.dd}\"\r\n\t}\r\n  }\r\n}" > /etc/logstash/conf.d/30-elasticsearch-output.conf

# Starting the service and enabling it on startup
sudo systemctl start logstash
sudo systemctl enable logstash

# Installing Filebeat
sudo apt install -y filebeat

# editing config files
printf "filebeat.inputs:\r\n- type: filestream\r\n\r\n  # Unique ID among all inputs, an ID is required.\r\n  id: my-filestream-id\r\n\r\n  # Change to true to enable this input configuration.\r\n  enabled: false\r\n\r\n  # Paths that should be crawled and fetched. Glob based paths.\r\n  paths:\r\n    - /var/log/*.log\r\n\r\nfilebeat.config.modules:\r\n  path: \${path.config}/modules.d/*.yml\r\n  reload.enabled: false\r\n\r\nsetup.template.settings:\r\n  index.number_of_shards: 1\r\n\r\n\r\nsetup.kibana:\r\n\r\noutput.logstash:\r\n  # The Logstash hosts\r\n  hosts: [\"localhost:5044\"]\r\n\r\n\r\nprocessors:\r\n  - add_host_metadata:\r\n      when.not.contains.tags: forwarded\r\n  - add_cloud_metadata: ~\r\n  - add_docker_metadata: ~\r\n  - add_kubernetes_metadata: ~\r\n" > /etc/filebeat/filebeat.yml

# Enabling system and zeek modules
sudo filebeat modules enable system
sudo filebeat modules enable zeek

# Setting up piplines for the modules
sudo filebeat setup --pipelines --modules system
sudo filebeat setup --pipelines --modules zeek

sudo filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'
sudo filebeat setup -E output.logstash.enabled=false -E output.elasticsearch.hosts=['localhost:9200'] -E setup.kibana.host=localhost:5601

# Starting the service and enabling it on startup
sudo systemctl start filebeat
sudo systemctl enable filebeat

# installing zeek and rita
sudo apt install -y git
cd ~
git clone https://github.com/activecm/rita.git

cd rita

chmod +x install.sh 
# this installs zeek and sets it up to sniff on the user specified interface
sudo ./install.sh --disable-mongo

# installing mongo for rita, latest version is not supported
wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-debian10-4.2.23.tgz
tar -xvzf mongodb-linux-x86_64-debian10-4.2.23.tgz

# needed package to run mongo on lateest ubuntu systems
wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb

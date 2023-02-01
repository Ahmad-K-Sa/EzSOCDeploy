# Java installation
// doesnt work may remove
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get update
sudo apt-get -y install oracle-java8-installer
//doesnt work below does
sudo apt install openjdk-11-jre-headless

# ElasticSearch Installation
echo "importing elasticsearch public GPG key into apt"
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

echo "creating elasticsearch source list"
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list

sudo apt-get update
sudo apt-get -y install elasticsearch
sudo apt-get -y install elasticsearch --allow-unauthenticated
echo "network.host: localhost" >> /etc/elasticsearch/elasticsearch.yml

# Restarting Elasticseatch
sudo service elasticsearch restart

# Start Elastic on bootup
sudo update-rc.d elasticsearch defaults 95 10

# Kibana Installation
echo "Kibanan Installation"

echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-4.5.x.list

sudo apt-get update

sudo apt-get install kibana --allow-unauthenticated

echo server.host: "localhost" >> /etc/kibana/kibana.yml 

sudo update-rc.d kibana defaults 96 9
sudo service kibana start


# Nginx Installation
echo "Nginx installation"

sudo apt-get install nginx apache2-utils
sudo htpasswd -c /etc/nginx/htpasswd.users kibanaadmin

printf "server {\n    listen 80;\n    server_name example.com;\n    auth_basic \"Restricted Access\";\n    auth_basic_user_file /etc/nginx/htpasswd.users;\n    location \ {\n        proxy_pass http://localhost:5601;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade \$http_upgrade;\n        proxy_set_header Connection 'upgrade';\n        proxy_set_header Host \$host;\n        proxy_cache_bypass \$http_upgrade;\n    }\n}" > /etc/nginx/sites-available/default 

sudo service nginx restart


echo "Kibana is now accessible via your FQDN or the public IP address of your ELK Server i.e. http://elk-server-public-ip/"




// Logstash installation
echo 'deb http://packages.elastic.co/logstash/2.2/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash-2.2.x.list

sudo apt-get update

sudo apt-get install logstash

# Generate SSL Certificates
sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private

ip="ip a | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'"
ip=$(eval "$ip")

sed -i -e "s/^\[ v3\_ca \]$/\[ v3\_ca \]\nsubjectAltName = IP\: $ip/g" /etc/ssl/openssl.cnf

# Generate SSL Certificates
cd /etc/pki/tls
sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt


# Logstash Configuration

sudo vi /etc/logstash/conf.d/02-beats-input.conf

// Type this
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
//

# Adding syslog filter

sudo vi /etc/logstash/conf.d/10-syslog-filter.conf

//
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
//

sudo vi /etc/logstash/conf.d/30-elasticsearch-output.conf


// Type this
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
//

# Restart Logstash
sudo service logstash configtest

// Should show COnfiguration OK

# Restart and setup on restart
sudo service logstash restart
sudo update-rc.d logstash defaults 96 9


# Kibana Dashboards Setup
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip

sudo apt-get -y install unzip
unzip beats-dashboards-*.zip

# Load dashboard
cd beats-dashboards-*
./load.sh


# Filebeat configuration
cd ~
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json

//
If the template loaded properly, you should see a message like this:

Output:
{
  "acknowledged" : true
}
//
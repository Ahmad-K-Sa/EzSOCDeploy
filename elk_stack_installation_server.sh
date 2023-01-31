# Java 8 installation

sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get update
sudo apt-get -y install oracle-java8-installer

# ElasticSearch Installation
echo -n "importing elasticsearch public GPG key into apt"
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

echo -n "creating elasticsearch source list"
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list

sudo apt-get update
sudo apt-get -y install elasticsearch
sudo vi /etc/elasticsearch/elasticsearch.yml

// TODO Prevent access using editing network.host: localhost

# Restarting Elasticseatch
sudo service elasticsearch restart

# Start Elastic on bootup
sudo update-rc.d elasticsearch defaults 95 10


# Kibana Installation
echo -n "Kibanan Installation"

echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-4.5.x.list

sudo apt-get update

sudo apt-get -y install kibana


// Need manual stuff
sudo vi /opt/kibana/config/kibana.yml

In the Kibana configuration file, find the line that specifies server.host, and replace the IP address (“0.0.0.0” by default) with “localhost”:
server.host: "localhost"
// Need manual stuff

sudo update-rc.d kibana defaults 96 9
sudo service kibana start


# Nginx Installation
echo -n "Kibanan Nginx"

sudo apt-get install nginx apache2-utils
sudo htpasswd -c /etc/nginx/htpasswd.users kibanaadmin

// Need manual stuff here

sudo vi /etc/nginx/sites-available/default

// Need to add the following 

server {
    listen 80;

    server_name example.com;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;        
    }
}

//

sudo service nginx restart


Kibana is now accessible via your FQDN or the public IP address of your ELK Server i.e. http://elk-server-public-ip/




// Logstash installation
echo 'deb http://packages.elastic.co/logstash/2.2/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash-2.2.x.list

sudo apt-get update

sudo apt-get install logstash

# Generate SSL Certificates
sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private

sudo vi /etc/ssl/openssl.cnf

// Manual Work

subjectAltName = IP: ELK_server_private_IP


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
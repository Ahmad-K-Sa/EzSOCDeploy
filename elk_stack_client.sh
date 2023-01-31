# copy ssl certificate from server 
scp /etc/pki/tls/certs/logstash-forwarder.crt user@client_server_private_address:/tmp

sudo mkdir -p /etc/pki/tls/certs
sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/

# Filebeat installation
echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee -a /etc/apt/sources.list.d/beats.list
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get update
sudo apt-get install filebeat

# Filebeat configuration
sudo vi /etc/filebeat/filebeat.yml

// add these
...
      paths:
        - /var/log/auth.log
        - /var/log/syslog
#        - /var/log/*.log
...

Then find the line that specifies document_type:, uncomment it and change its value to “syslog”. It should look like this after the modification:
      document_type: syslog
//

# Restart Filebeat
sudo service filebeat restart
sudo update-rc.d filebeat defaults 95 10

#!/bin/bash

sudo mkdir -p /opt/arcana/conf
sudo mkdir /opt/arcana/plugins 
sudo mkdir /opt/arcana/bin
sudo cp default_config/arcana.conf /opt/arcana/conf/arcana.conf
sudo cp plugins/*.o /opt/arcana/plugins
sudo cp build/arcana /usr/bin/arcana
sudo cp build/arcana /opt/arcana/bin

echo 'Created /opt/arcana directory and installed necessary files for Arcana.Elfscan'

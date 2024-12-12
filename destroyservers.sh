#!/bin/bash

DOMLIST=$(virsh -q list --all | awk '{ print $2 }')
VOLLIST=$(virsh -q vol-list default | awk '{ print $2 }')

for server in $DOMLIST; do 
  virsh destroy $server
  virsh undefine $server
done

for volume in $VOLLIST; do
  virsh vol-delete $volume
done

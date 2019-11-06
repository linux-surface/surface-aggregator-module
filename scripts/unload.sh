#!/usr/bin/env bash
#
# Script to unload all in-kernel modules.
#

sudo systemctl stop surface-dtx-daemon.service

sudo modprobe -r surface_sam_dtx
sudo modprobe -r surface_sam_sid
sudo modprobe -r surface_sam_vhf
sudo modprobe -r surface_sam_san
sudo modprobe -r surface_sam_ssh

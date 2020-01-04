#!/usr/bin/env bash
#
# Script to unload all in-kernel modules.
#

sudo systemctl stop surface-dtx-daemon.service

sudo modprobe -r surface_sam_sid_vhf
sudo modprobe -r surface_sam_sid_perfmode
sudo modprobe -r surface_sam_sid_gpelid
sudo modprobe -r surface_sam_sid
sudo modprobe -r surface_sam_hps
sudo modprobe -r surface_sam_dtx
sudo modprobe -r surface_sam_vhf
sudo modprobe -r surface_sam_san
sudo modprobe -r surface_sam_ssh

# vagrant plugin install vagrant-qemu
# vagrant box add generic/alpine316 --provider=libvirt
# vagrant up --provider=qemu
# shared folders: first password is same as host OS / username needs to be host OS username / second password is same password as host OS
# wait for it to come up
# vagrant ssh
# sudo apk add curl gcc nodejs openssl-dev npm
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# source "$HOME/.cargo/env"
# cd /mnt/scripts
# npm install
# cd /mnt
# ./scripts/run.sh
Vagrant.configure("2") do |config|
  config.vm.box = "generic/alpine311"
  config.vm.provider "qemu" do |qe|
    qe.arch = "x86_64"
    qe.machine = "q35"
    qe.cpu = "max"
    qe.net_device = "virtio-net-pci"
  end
  config.vm.synced_folder ".", "/mnt", type: "smb"
end

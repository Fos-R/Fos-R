Vagrant.configure("2") do |config|
  ["vm1", "vm2"].each do |vm_name|
    config.vm.define vm_name do |vm|
      vm.vm.box = "debian/bookworm64"
      vm.vm.hostname = vm_name
      vm.vm.network "private_network", type: "static", ip: "192.168.56.10#{vm_name[-1]}"
      vm.vm.synced_folder ".", "/vagrant", disabled: true
      vm.vm.synced_folder ".", "/home/vagrant/fosr"

      vm.vm.synced_folder "/nix/store", "/nix/store"

      vm.vm.provision "shell", privileged:false, inline: <<-SHELL
        sudo apt update
        sudo apt install -y libpcap-dev tcpdump
      SHELL
    end
  end
end

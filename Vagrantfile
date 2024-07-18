Vagrant.configure("2") do |config|
  config.vm.define "build" do |config|
    config.vm.box = "ubuntu/jammy64"
    config.vm.provider "virtualbox" do |vb|
      vb.memory = "8192"
      vb.cpus = 8
    end
    config.vm.synced_folder ".", "/home/vagrant/build"
    config.vm.provision "shell", privileged: true, inline: <<-SHELL
      apt update
      apt install -y build-essential autoconf clang-15 flex bison pkg-config autopoint
      ln -s /usr/include/asm-generic /usr/include/asm
      rm -f /bin/clang && ln -s /usr/bin/clang-15 /bin/clang

      snap install rustup --classic
    SHELL

    config.vm.provision "shell", inline: <<-SHELL
      rustup default stable
      cd vagrant && cargo build --release
    SHELL
  end

  config.vm.define "test"  do |config|
    config.vm.box = "ubuntu/jammy64"
    config.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
    config.vm.synced_folder "./target", "/home/vagrant/target"
  end
end
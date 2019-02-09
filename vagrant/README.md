<img src="https://media.licdn.com/mpr/mpr/AAEAAQAAAAAAAAdYAAAAJGMyOGY0NTA1LWFiOTAtNDE3Yi1iYWRkLTM0MjczNGQ3MzdhNA.png" align="right" width="30%" height="30%"/>

# Vagrant

Here you will find a `Vagrantfile` to build a development environment for `kvm-vmi`.

# Requirements

- `vagrant`
- [`vagrant-libvirt`](https://github.com/vagrant-libvirt/vagrant-libvirt) plugin
- [`vagrant-reload`](https://github.com/aidanns/vagrant-reload) plugin
- `ansible >= 2.7.0`

# Setup

Install `Vagrant` plugins:

~~~
$ vagrant plugin install vagrant-libvirt vagrant-reload
~~~

Install `Ansible`

~~~
$ virtualenv venv
$ source venv/bin/activate
(venv) $ pip install ansible
~~~


## Vagrantfile

Tune the Vagrantfile configuration to your needs.

- `cpus`
- `memory` (in `MB`)

## Build the environment

- run `vagrant up` and wait for the setup to be completed

~~~
(venv) $ vagrant up
==> default: Removing domain...
==> default: Running cleanup tasks for 'reload' provisioner...
Bringing machine 'default' up with 'libvirt' provider...
==> default: Created volume larger than box defaults, will require manual resizing of
==> default: filesystems to utilize.
==> default: Creating image (snapshot of base box volume).
==> default: Creating domain with the following settings...
...
~~~


ssh into the box with `vagrant ssh`


## Note: NFS

NFS may need additonal configuration:

You need to open your firewall for `NFS`. The following commands should make it work for a `Vagrant` box
to access your host `NFS` server:

~~~
firewall-cmd --permanent --add-service=nfs
firewall-cmd --permanent --add-service=rpc-bind
firewall-cmd --permanent --add-service=mountd
firewall-cmd --reload
~~~

#!/usr/bin/env python
# coding=utf-8

import sys
import os

try:
    from docker import APIClient as Client
except ImportError:
    from docker import Client 
import docker

file = '/yuyuyu'

cli = Client(base_url='unix://var/run/docker.sock')
# exec_id = cli.exec_create(container='2538c62e958a', cmd='mkdir -p ' + file)
# cli.exec_start(exec_id=exec_id)


# 功能函数


def mkdir(container, path):
    cmd = "mkdir -p " + path
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    cli.exec_start(exec_id=exec_id)


def cd(container, path, use_shell=False):
    cmd = "/bin/bash -c 'cd " + path + "'"
    print("$:", cmd)
    if not use_shell:
        exec_id = cli.exec_create(container=container.short_id, cmd=cmd, tty=True)
        res = str(cli.exec_start(exec_id=exec_id, tty=True).decode())
        print(res)
    else:
        # 直接使用docker自带的守护进程进行shell脚本控制
        pass


def get_cert(container, path):
    cmd = "fabric-ca-client getcacert -M " + path + "msp"
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    cli.exec_start(exec_id=exec_id)


def register(container, ca_type, ca_name, affiliation):
    cmd = "fabric-ca-client register --id.name " + \
          ca_name[0] + " --id.type " + ca_type + " --id.affiliation " + \
          affiliation + " --id.secret " + ca_name[1] + \
          " --id.attrs \'\"" + "hf.Registrar.Roles=client,orderer,peer,user\"," + \
                       "\"hf.Registrar.DelegateRoles=client,orderer,peer,user\"," + \
                       "hf.Registrar.Attributes=*," + \
                       "hf.GenCRL=true,hf.Revoker=true,hf.AffiliationMgr=true," + \
                       "hf.IntermediateCA=true,role=admin:ecert" + \
          "\'"
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    res = str(cli.exec_start(exec_id=exec_id).decode()).split('\n')
    for i in res:
        print('\t' + i)


def enroll(container, user, ca_server, path, use_shell=False):
    cd(container, path, use_shell)
    # env(container, path)
    cmd = "cd " + path + " && pwd && env && " + "/usr/local/bin/fabric-ca-client enroll -u " + \
          "http://" + user[0] + ":" + user[1] + \
          "@" + ca_server[0] + ":" + str(ca_server[1]) + \
          " -H " + path
    cmd_bash = "/bin/bash -c '" + cmd + "'"

    if not use_shell:
        print("$:", cmd_bash)
        exec_id = cli.exec_create(container=container.short_id, cmd=cmd_bash, tty=True)
        res = str(cli.exec_start(exec_id=exec_id, tty=True).decode()).split('\n')
        for i in res:
            print("\t" + i)
    else:
        # 开启额外终端: gnome-terminal -x bash -c "ls ; exec bash;"
        # exec bash表示可以继续保持终端，不关闭。
        cmd_gnome_terminal = "gnome-terminal -x bash -c "
        cmd_docker_shell = cmd_gnome_terminal + "\"" + " docker exec -i " + container.id[0:12] + " " + cmd_bash + "; exec bash; \""

        print("$:", cmd_docker_shell)

        # 法一： 返回代码的是否成功字段，无法看到实际命令的返回结果
        # res = os.system(cmd_docker_shell)
        # print(res)

        # 法二： 可以看到返回结果，但是此处封装的是gnome_terminal的代码，也就同样看不到内部的docker指令的返回结果
        res = os.popen(cmd_docker_shell)
        # print(res.read())


def getIP(container):
    return cli.inspect_container(container.name).get('NetworkSettings').get('Networks').get('bridge').get('IPAddress')


def cp(container, src_path, des_path):
    cmd = "cp " + src_path + " " + des_path
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    cli.exec_start(exec_id=exec_id)


def rm(container, path):
    cmd = "rm -rf " + path + "/*"
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    cli.exec_start(exec_id=exec_id)


def delete_affiliation(container, path, org):
    cmd = "fabric-ca-client -H " + path + " affiliation remove --force " + org
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    cli.exec_start(exec_id=exec_id)


def create_affiliation(container, path, org):
    cmd = "fabric-ca-client -H " + path + " affiliation add " + org
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    cli.exec_start(exec_id=exec_id)


def show_affiliation(container, path):
    cmd = "fabric-ca-client -H " + path + " affiliation list "
    print("$:", cmd)
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    res = str(cli.exec_start(exec_id=exec_id).decode()).split('\n')
    for i in res:
        print("\t" + i)

def ls(container, path):
    cmd = "cd " + path + " && ls"
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    res = str(cli.exec_start(exec_id=exec_id).decode()).split('\n')
    # print(res)
    for i in res:
        print("\t" + i)


def env(container, path):
    cmd = "pwd " + path
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    res = str(cli.exec_start(exec_id=exec_id).decode()).split('\n')
    # print(res)
    for i in res:
        print("\t" + i)


def openssl(container, path):
    cmd = "openssl x509 -in " + path + " -inform pem -text"
    exec_id = cli.exec_create(container=container.short_id, cmd=cmd)
    res = str(cli.exec_start(exec_id=exec_id).decode()).split('\n')
    print("\nshow ca_file:", path)
    for i in res:
        if "Issuer:" in i or "Subject:" in i:
            print("\t" + i.strip())


############################################################################
#  0. 预操作
############################################################################

path_root = "/etc/hyperledger/fabric-ca-server/"
client = docker.from_env()

# 下载镜像
# client.images.pull('hyperledger/fabric-ca')

# 删除所有的ca文件
path_worker = "/opt/cello/fabric-1.0/crypto-config/"
cmd_rm_ca = "sudo rm -rf " + path_worker + "*"
print(cmd_rm_ca)
os.system(cmd_rm_ca)

# 删除所有容器
for container in cli.containers():
    cli.stop(container['Id'])
    cli.remove_container(container['Id'])
    print("remove ", container['Id'])
'''
[{'Id': 'bc01dee95fe7444591dc506a2caa205c413a44708fc719e458548e21c1e9fde8', 
'Names': ['/ca0'], 'Image': 'hyperledger/fabric-ca:amd64-1.2.0', 
'ImageID': 'sha256:66cc132bd09c7dcf5c1f7075f4b2b7b6304b3919cc73738ac2cd029a92901e4a', 
'Command': "sh -c 'fabric-ca-server start -b admin:adminpw --cfg.affiliations.allowremove --cfg.identities.allowremove '", 
'Created': 1536195245, 
'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 7054, 'PublicPort': 6000, 'Type': 'tcp'}], 
'Labels': {}, 'State': 'running', 'Status': 'Up 21 minutes', 
'HostConfig': {'NetworkMode': 'default'}, 'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': None, 'Links': None, 'Aliases': None, 
'NetworkID': '47402bcb77e02f29d1a665395ac5f9046622ff58b8ab5dbf432e945e82fa85ab', 'EndpointID': 'f05c7b506c72116e57cb82d0f3aa27d2cfbf138f7027edcacddf86fe21eb3141', 
'Gateway': '172.17.0.1', 
'IPAddress': '172.17.0.2', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:11:00:02', 'DriverOpts': None}}}, 
'Mounts': [{'Type': 'bind', 'Source': '/opt/cello/fabric-1.0/crypto-config', 'Destination': '/etc/hyperledger/fabric-ca-server/fabric-files', 'Mode': 'rw', 'RW': True, 'Propagation': 'rprivate'}]}]
'''

# 存放所有容器,{ca0:[ip, port]}
dict_containers = {}

############################################################################
#  1. CA0操作
############################################################################

# 1.1 创建ca0容器
ca0 = "ca0"
ca0_admin = ["ca0_admin", "adminpw"]
path_example_com = path_root + "fabric-files/" + "ordererOrganizations/example.com/"
ip_ca0 = "127.0.0.1"
port_ca0 = 6000
print("createing CA0")
container_ca0 = client.containers.create('hyperledger/fabric-ca:amd64-1.2.0',
    command="sh -c 'fabric-ca-server init -b " + ca0_admin[0] + ":" + ca0_admin[1] +
            " --cfg.affiliations.allowremove --cfg.identities.allowremove && " +
            " fabric-ca-server start -b " + ca0_admin[0] + ":" + ca0_admin[1] +
            " --cfg.affiliations.allowremove --cfg.identities.allowremove && "
            " fabric-ca-client enroll -u http://ca0_admin:adminpw@localhost:7054 -H "
            " /etc/hyperledger/fabric-ca-server/fabric-files/admin/ '",  # " --ca.name " + ca0 +
    ports={'7054/tcp': (ip_ca0, port_ca0)},
    environment=["t=1"],
    volumes={"/opt/cello/fabric-1.0/crypto-config/": {"bind": path_root+"fabric-files/", "mode": "rw"}},
    name=ca0)
print("created!")
container_ca0.start()
ip_ca0 = getIP(container_ca0)
port_ca0 = '7054'
dict_containers[container_ca0.name] = ip_ca0
print("container_ca0: " + ip_ca0 + ":" + port_ca0)

# 1.2 生成fabric-ca0 admin的凭证
path_admin = path_root + "fabric-files/admin/"
mkdir(container_ca0, path_admin)

enroll(container_ca0, ca0_admin, [ip_ca0, port_ca0], path_admin, use_shell=True)

input()
get_cert(container_ca0, path_admin)

# 拷贝ca-cert.pem证书文件
path_ca0_cert = path_root + "ca-cert.pem"
# cp(container_ca0, src_path=path_root+"ca-cert.pem", des_path=path_admin+"msp/cacerts/")
openssl(container=container_ca0, path=path_ca0_cert)

# 1.3 创建组织联盟结构affiliation
# 1.3.0 需要先登录
enroll(container_ca0, ca0_admin, [ip_ca0, port_ca0], path_admin)

# 1.3.1 查看已有的affiliation
print("查看删除前的affiliation：")
show_affiliation(container=container_ca0, path=path_admin)

# 1.3.2 先删除自带的affiliation
delete_affiliation(container=container_ca0, path=path_admin, org="org1.department1")
delete_affiliation(container=container_ca0, path=path_admin, org="org1.department2")
delete_affiliation(container=container_ca0, path=path_admin, org="org1")
delete_affiliation(container=container_ca0, path=path_admin, org="org2.department1")
delete_affiliation(container=container_ca0, path=path_admin, org="org2")

print("查看删除后的affiliation：")
show_affiliation(container=container_ca0, path=path_admin)

# 1.3.3 再创建需要的affiliation
create_affiliation(container=container_ca0, path=path_admin, org="com")
create_affiliation(container=container_ca0, path=path_admin, org="com.example")
create_affiliation(container=container_ca0, path=path_admin, org="com.example.org1")
create_affiliation(container=container_ca0, path=path_admin, org="com.example.org2")

print("查看创建后的affiliation：")
show_affiliation(container=container_ca0, path=path_admin)

input()

# 1.4 为多个联盟准备msp
mkdir(container_ca0, path_root + "fabric-files/" + "ordererOrganizations")
mkdir(container_ca0, path_root + "fabric-files/" + "peerOrganizations")


'''
结构模式：
ordererOrganizations
    - example.com
        - ca: 文件ca.example.com-cert.pem, xxx_sk
        - msp: 包含admincerts, cacerts, keystore, signcerts, tlscacerts
            - admincerts/Admin@example.com-cert.pem
            - cacerts/ca.example.com-cert.pem
            - tlscacerts/tlsca.example.com-cert.pem
        - orderers:
            - orderer.example.com
                - msp: 包含admincerts, cacerts, keystore, signcerts, tlscacerts
                - tls: 文件ca.crt, server.crt, server.key
        - tlsca
        - users:
            - Admin@example.com
                - msp: 包含admincerts, cacerts, keystore, signcerts, tlscacerts
                - tls: 文件ca.crt, server.crt, server.key
peerOrganizations
    - org1.example.com
        - ca: 文件ca.org1.example.com-cert.pem, xxx_sk
        - msp: admincerts, cacerts, tlscacerts
        - peers:
            - peer0.org1.example.com
                - msp: admincerts, cacerts, keystore, signcerts, tlscacerts
                - tls: 文件ca.crt, server.crt, server.key
        - tlsca: 文件tlsca.org1.example.com-cert.pem, xxx_sk
        - users
            - Admin@org1.example.com
                - msp: admincerts, cacerts, keystore, signcerts, tlscacerts
                - tls: ca.crt, server.crt, server.key
            - User1@org1.example.com
                - msp: admincerts, cacerts, keystore, signcerts, tlscacerts
                - tls: ca.crt, server.crt, server.key

'''

# 1.4.1 example.com
path_example_com = path_root + "fabric-files/" + "ordererOrganizations/example.com/"
get_cert(container_ca0, path_example_com)

# 1.4.2 example.com/orderers
path_orderer = path_example_com + "orderers/orderer.example.com/"
get_cert(container_ca0, path_orderer)

# # 1.4.3 example.com/users
# path_orderer_user = path_example_com + "users/Admin@example.com/"
# get_cert(container_ca0, path_orderer_user)

# 1.4.4 peerOrganizations/org1.example.com
path_org1 = path_root + "fabric-files/" + "peerOrganizations/org1.example.com/"
path_org1_msp = path_org1 + "msp/"
get_cert(container_ca0, path_org1)

# # 1.4.5 peerOrganizations/org1.example.com/peers
# path_org1_peer0 = path_org1 + "peers/peer0.org1.example.com"
# get_cert(container_ca0, path_org1_peer0)
#
# # 1.4.6 org1.example.com/users
# path_org1_admin = path_org1 + "users/Admin@org1.example.com"
# path_org1_user1 = path_org1 + "users/User1@org1.example.com"
# get_cert(container_ca0, path_org1_admin)
# get_cert(container_ca0, path_org1_user1)


# 先用单个ca0生成的方式
def single_create():
    # 1.
    # example.com的register
    com = "com"
    example = "example.com"
    example_ca = ["example.com", "adminpw"]
    path_example_com = path_root + "fabric-files/" + "ordererOrganizations/example.com/"

    register(container_ca0, ca_type="client",
             ca_name=example_ca,
             affiliation=com)

    # example.com的enroll
    enroll(container_ca0, example_ca, [ip_ca0, port_ca0], path_example_com)

    # 2.
    # orderer.example.com的register
    orderer_ca = ["orderer.example.com", "adminpw"]
    orderer_example = "orderer.example.com"
    register(container_ca0, ca_type="orderer",
             ca_name=orderer_ca,
             affiliation=example)
    ip_ca1_orderer = "127.0.0.1"
    port_ca1_orderer = 6002
    path_orderer_example_com = path_orderer + "msp/certs/"
    # orderer.example.com的enroll
    enroll(container_ca0, orderer_ca, [ip_ca0, port_ca0], path_example_com)



single_create()

input()

# ############################################################################
# #  2. orderer创建
# ############################################################################
# # 1. 创建example.com的ca容器
# com = "com"
# example = "example.com"
# example_ca = ["example.com", "adminpw"]
# path_example_com = path_root + "fabric-files/" + "ordererOrganizations/example.com/"
#
#
# register(container_ca0, ca_type="client",
#          ca_name=example_ca,
#          affiliation=com)
# print("creating example")
# container_ca1_example = client.containers.create('hyperledger/fabric-ca:amd64-1.2.0',
#     command="sh -c 'fabric-ca-server start -b " + example_ca[0] + ":" + example_ca[1] +
#         " --cfg.affiliations.allowremove --cfg.identities.allowremove'" +
#         " -u http://" + example_ca[0] + ":" + example_ca[1] + "@" + str(ip_ca0) + ":" + str(port_ca0),
#     ports={7054: None},
#     environment=["t=t1"],
#     volumes={"/opt/cello/fabric-1.0/crypto-config/": {"bind": path_root+"fabric-files/", "mode": "rw"}},
#     name='ca1')
# print("created!")
# container_ca1_example.start()
# ip_ca1_example = getIP(container_ca1_example)
# port_ca1_example = '7054'
# dict_containers[container_ca1_example.name] = ip_ca1_example
# print("container_ca1_example:", ip_ca1_example, port_ca1_example)
#
# # 2. 生成Admin@example.com的ca证书
# path_example_com_admin = path_example_com + "users/Admin@example.com"
# mkdir(container_ca1_example, path_example_com_admin)
# enroll(container_ca1_example, example_ca, [ip_ca1_example, port_ca1_example], path_example_com_admin)
#
# # 3.
#
# # 1. 注册orderer.example.com的管理员Admin@orderer.example.com
# orderer_ca = ["orderer.example.com", "adminpw"]
# orderer_example = "orderer.example.com"
# register(container_ca1_example, ca_type="orderer",
#          ca_name=orderer_ca,
#          affiliation=example)
# ip_ca1_orderer = "127.0.0.1"
# port_ca1_orderer = 6002
# print("creating orderer")
# container_ca2_orderer_example = client.containers.create('hyperledger/fabric-ca:amd64-1.2.0',
#     command="sh -c 'fabric-ca-server start -b " + orderer_ca[0] + ":" + orderer_ca[1] +
#         " --cfg.affiliations.allowremove --cfg.identities.allowremove'" +
#         " -u http://" + orderer_ca[0] + ":" + orderer_ca[1] + "@" + str(ip_ca1_example) + ":" + str(port_ca1_orderer),
#     ports={7054: (ip_ca1_orderer, port_ca1_orderer)},
#     environment=["t=t1"],
#     volumes={"/opt/cello/fabric-1.0/crypto-config/": {"bind": path_root+"fabric-files/", "mode": "rw"}},
#     name='ca2')
# print("created!")
#
# container_ca2_orderer_example.start()
# ip_ca1_orderer = getIP(container_ca2_orderer_example)
# port_ca1_orderer = '7054'
# dict_containers[container_ca2_orderer_example.name] = ip_ca1_orderer
# print("container_ca2_orderer_example:", ip_ca1_orderer, port_ca1_orderer)
# # 2. 登录orderer.example.com


# ############################################################################
# #  2. CA1创建
# ############################################################################
# org1 = 1
# org1_ = "org" + str(org1) + ".example.com"
# org1_ca = "ca1@org1.example.com", "org1pw"
# org1_admin = ["Admin@org1.example.com", "adminpw"]
# org1_peer0 = ["Peer0@org1.example.com", "peer0pw"]
# org1_peer1 = ["Peer0@org1.example.com", "peer0pw"]
#
# register(container_ca0, ca_type="peer",
#          ca_name=org1_ca,
#          affiliation=org1_)
#
# print("creating CA1_org1")
# container_ca1 = client.containers.create('hyperledger/fabric-ca:amd64-1.2.0',
#     command="sh -c 'fabric-ca-server start -b admin:adminpw \
#         --cfg.affiliations.allowremove --cfg.identities.allowremove'",
#     ports={7054: None},
#     environment=[""],
#     volume={"/opt/cello/fabric-1.0/crypto-config/": {"bind": path_root+"fabric-files/", "mode": "rw"}},
#     name='ca1')
#
#
# ############################################################################
# #  3. peer0.org1.example.com创建
# ############################################################################
# register(container_ca0, ca_type="peer",
#          ca_name="peer1",
#          affiliation="org1.example.com")
# print("creating peer0.org1.example.com")
# container_ca1_peer0 = client.containers.create('hyperledger/fabric-ca:amd64-1.2.0',
#     command="sh -c 'fabric-ca-server start -b admin:adminpw \
#         --cfg.affiliations.allowremove --cfg.identities.allowremove'",
#     ports={7054: None},
#     environment=[""],
#     volumes={"/opt/cello/fabric-1.0/crypto-config/": {"bind": path_root+"fabric-files/", "mode": "rw"}},
#     name='ca1_peer0')
#
# # 删除容器
# container_ca1_peer0.stop()
# container_ca1_peer0.remove()


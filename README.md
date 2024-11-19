# QGroundControl for secure mavlink
This repository(branch) contains 'secure mavlink' implementation.
Based version is from [Daily build, Sep 23 2024, 26954d500](https://github.com/Lumy0726/qgroundcontrol/tree/securemav_before/).
Please see the below link for the original README document.

[README](./README_orig.md/)

# Secure mavlink
Below list is implementations to enhance security of mavlink protocol.  
* Apply payload encryption of MAVLink protocol.

## Payload encryption of MAVLink protocol
Below list is implementations to apply payload encryption.
* Modify 'libs/mavlink/include/mavlink/v2.0' submodule commit, to use encryption supported MAVLink protocol.  
But this submodule is ignored while build processing for now, submodule version is controlled by '[src/MAVLink/CMakeLists.txt](./src/MAVLink/CMakeLists.txt)', therefore it's configuration has been modified.  
Actual implementation is on [pymavlink](https://github.com/Lumy0726/pymavlink/tree/securemav/) repository.  
* To use AES128 CTR encryption method, include external library, using source file copy, to [src/MAVLink](./src/MAVLink).  
[original library implementation reference](https://github.com/Lumy0726/PX4-Autopilot/tree/mesl_lib/src/modules/mesl_crypto/)  
* Modify '[src/MAVLink](./src/MAVLink)' source code to enable encryption.  
Encryption will be automatically enabled if communication opponent sends encryted MAVLink frame. This will be handled per MAVLink channel.  
Some debugging code also has been implemented, and can be toggled using C macro variable.  


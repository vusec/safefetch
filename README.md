This repository contains the source code for a Linux-based prototype of SafeFetch. The prototype is based on the 
*SafeFetch: Practical Double-Fetch Protection with Kernel-Fetch Caching* [paper](https://download.vusec.net/papers/safefetch_sec24.pdf) accepted for publication at the *33rd Usenix Security Symposium*, 2024.

For steps of reproducing the results presented in our paper check our [artifact](https://github.com/vusec/safefetch-ae) which
received the [badges](https://secartifacts.github.io/usenixsec2024/instructions#usenixbadgessty--affix-usenix-artifact-evaluation-badges) *artifact available*, *artifact functional*
and *artifact reproduced* during USENIX Security '24 Call for Artifacts. 

## Commands to build and install a SafeFetch protected kernel 

The following commands will clone the repository in the safefetch local dir and build a default kernel 
protected with SafeFetch. 

```bat
git clone git@github.com:vusec/safefetch.git safefetch
make -C safefetch mrproper
make -C safefetch x86_64_defconfig
cd safefetch && ./scripts/config -d CONFIG_AUDITSYSCALL -e CONFIG_SAFEFETCH && cd ..
make -C safefetch 
sudo make -C safefetch install

```

## Enable SafeFetch during runtime

SafeFetch is enabled during runtime using static keys. After booting into the new kernel copy
the following bash commands in a script named *safefetch_control.sh*.

```bat
#!/bin/bash

# Hook initialization has to be a one time only event.
XSLEEP=2

init_defense () {
    if [[ $1 == '-linklist' ]];
    then
       CONFIG=0
    elif [[ $1 == '-rbtree' ]];
    then
       CONFIG=1
    elif [[ $1 == '-adaptive' ]];
    then
       CONFIG=2
    elif [[ $1 == '-storage' ]];
    then
       # When updating the region sizes flip off defense (we don't want
       # concurent accesses).
       echo "0" | sudo tee /sys/dfcacher_keys/copy_from_user_key_ctrl
       sleep ${XSLEEP}

       echo "$2 $3 $4" | sudo tee /sys/dfcacher_keys/storage_regions_ctrl

       echo "1" | sudo tee /sys/dfcacher_keys/copy_from_user_key_ctrl
       sleep ${XSLEEP}

       return 0 
    elif [[ $1 == '-hooks' ]];
    then
       # Warning call this once, and it can never be set to 0 on this run.
       echo "1" | sudo tee /sys/dfcacher_keys/hooks_key_ctrl
       sleep ${XSLEEP}
       return 0 
    elif [[ $1 == '-enable' ]];
    then
       # We would like to flip defense hooks as well but this causes a race condition.
       #echo "1" | sudo tee /sys/dfcacher_keys/hooks_key_ctrl
       #sleep ${XSLEEP}
       # Just turn off defense if we get a different param
       echo "1" | sudo tee /sys/dfcacher_keys/copy_from_user_key_ctrl
       sleep ${XSLEEP}
       echo "Enabled DFCacher"
       return 0   
    else
       # Just turn off defense if we get a different param
       echo "0" | sudo tee /sys/dfcacher_keys/copy_from_user_key_ctrl
       sleep ${XSLEEP}
       echo "Disabled DFCacher"
       return 0    
    fi

    # Disable user copy protection.
    echo "0" | sudo tee /sys/dfcacher_keys/copy_from_user_key_ctrl
    sleep ${XSLEEP}

    [[ !  -z  $2  ]] &&  echo "$2 $3 $4" | sudo tee /sys/dfcacher_keys/storage_regions_ctrl
    sleep ${XSLEEP}

    if [ "$CONFIG" == "2" ]; then  
        [[ !  -z  $5  ]] &&  echo "$5" | sudo tee /sys/dfcacher_keys/adaptive_watermark_ctrl
        sleep ${XSLEEP}
    fi

    # Modify defense configuration
    echo ${CONFIG} | sudo tee /sys/dfcacher_keys/defense_config_ctrl
    sleep ${XSLEEP}

    # Bring copy from user hooks back online.
    echo "1" | sudo tee /sys/dfcacher_keys/copy_from_user_key_ctrl
    sleep ${XSLEEP}

    echo "Defense Configuration:  "$1 $2 $3

    return 0
}

init_defense $1 $2 $3 $4 $5


```


To enable Safefetch execute the following commands:

```bat
// enable syscall hooks for metadata/data management (must be called before any other control command)
./safefetch_control.sh -hooks
 // enable safefetch in adaptive mode
./safefetch_control.sh -adaptive 4096 4096 0
// disable safefetch
./safefetch_control.sh 
 // enable safefetch in rbtree mode
./safefetch_control.sh -rbtree 4096 4096 0
```



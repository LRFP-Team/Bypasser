# Bypasser

This is a developing rooting-layer system module for systematically bypassing environment detection related to LRFP for Android devices, where the abbreviation "LRFP" stands for Low-level, Rooting, Frameworks, and Plugins. 

This module will only take effect when users install it or click the ``action`` button. The current supported features are as follows. 

- Welcome (0b00000X): Perform built-in configurations for this module. 
- Zygisk Traces (0b0000X0): Deploy correct configurations for different Zygisk solutions according to the Zygisk implementation, Shamiko, NoHello, and Zygisk Assistant modules used. 
- HMA Configurations (0b000X00): Generate configurations for HMA and its branches based on cloud libraries (along with the web UI updating) and local packages. Users are required to manually import the configurations via HMA or its branches. Networks to GitHub are optional. 
- Tricky Store (0b00X000): Generate Tricky Store configurations directly based on cloud libraries. The configurations will be written to the Tricky Store configuration folder directly. Networks to GitHub are optional. 
- Shell (0b0X0000): Perform some shell commands. Please check ``actionA.sh`` for details. 
  - Disable sensitive applications automatically installed by Google. 
  - Remove sensitive policies. 
  - Handle properties. 
  - Enforce SELinux. 
  - Check whether the kernel involves banned strings. 
  - Patch ``/etc/compatconfig/services-platform-compat-config.xml``
  - Enable the feature of hiding desktop icons on devices running Android 10 or above. 
- Update (0bX00000): Perform regular dynamic updates for ``actionA.sh``, ``actionB.sh``, and the web UI (processed in the HMA Configuration stage). Networks to GitHub are required. 

Please kindly be aware that this module will only optimize the rooting and injection environments based on the current environments. 
This module will not include, install, enable, disable, or uninstall any other modules or plugins. 
The implementation and bypassing of these environments should be challenging and complex procedures. Users should learn related knowledge before taking these actions. 
Relying on one-key solutions or paying others for remote or onsite LRFP environment implementation, detection, or bypassing without knowing the principles is incorrect. 

## Compilation

If you want to build the module for testing purposes on your own, please use ``git clone`` to clone this repository to your local device.

Execute ``./build.sh`` in the root folder of the local repository after you check carefully and grant suitable execution permissions. 

Submit modifications via a pull request (PR) if you wish to. 

## Acknowledgement

Here, we express our faithful gratitude to all the LRFP-related developers, especially the developers of different rooting solutions and the detailed guidelines for rooting-layer system module development. 

We also sincerely thank [@pumPCin](https://github.com/pumPCin) for providing old HMA(L) configuration folders in [https://github.com/pumPCin/HMAL/issues/50](https://github.com/pumPCin/HMAL/issues/50). 

## Licensing

This repository is under the ``GPL-3.0`` license. 

You can regard this repository as an alternative rooting-layer system module template or a template GitHub repository for rooting-layer system module development. The A/B architecture is implemented for the dynamic updating of ``action``. 

## Warning

Since the project is still developing, please do not install the module here until this warning is removed in the future. 

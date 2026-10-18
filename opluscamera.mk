# OPlus Camera source tree
OPLUS_CAMERA_PATH := device/oneplus/infiniti-camera

# Blob dependencies
PRODUCT_PACKAGES += \
    aon.frameworkres.overlay.product \
    android.hardware.graphics.common-V3-ndk.vendor \
    oplus-services \
    Photos

# Camera extension runtime libraries needed by libcsextimpl.so
PRODUCT_PACKAGES += \
    android.frameworks.cameraservice.common@2.0 \
    android.frameworks.cameraservice.device@2.0 \
    android.frameworks.cameraservice.service@2.2 \
    android.hardware.camera.device-V4-ndk \
    android.hardware.camera.provider-V4-ndk \
    android.hardware.camera.provider@2.7 \
    libcameraservice \
    libdynamic_depth

# OplusSecurityPermissionLifecycle loads this jar explicitly from /system/framework.
# It must not be in PRODUCT_SYSTEM_SERVER_JARS: that classpath requires dexpreopt,
# while the OOS 16 jar has power-key classes incompatible with Android 17.
# Keep it installed via PRODUCT_PACKAGES and skip only this jar's dexpreopt.
PRODUCT_DEX_PREOPT_MODULE_CONFIGS += oplus-services=disable

# Framework
# PRODUCT_BOOT_JARS += \
#    oplus-framework

# Init
#PRODUCT_PACKAGES += \
#    init.oplus.camera.rc

# Permissions
PRODUCT_COPY_FILES += \
    $(OPLUS_CAMERA_PATH)/configs/init/init.oplus.camera_rus.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.oplus.camera_rus.rc \
    $(OPLUS_CAMERA_PATH)/configs/extension/com.oplus.app-features.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/extension/com.oplus.app-features.xml \
    $(OPLUS_CAMERA_PATH)/configs/permissions/default-permissions-com.aiunit.aon.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/default-permissions/default-permissions-com.aiunit.aon.xml \
    $(OPLUS_CAMERA_PATH)/configs/permissions/default-permissions-com.oplus.melody.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/default-permissions/default-permissions-com.oplus.melody.xml \
    $(OPLUS_CAMERA_PATH)/configs/permissions/com.oplus.android-features.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/permissions/com.oplus.android-features.xml \
    $(OPLUS_CAMERA_PATH)/configs/permissions/com.oplus.pantanal.ums.privapp_permissions.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/permissions/com.oplus.pantanal.ums.privapp_permissions.xml \
    $(OPLUS_CAMERA_PATH)/configs/permissions/oplus_google_lens_config.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/permissions/oplus_google_lens_config.xml \
    $(OPLUS_CAMERA_PATH)/configs/permissions/privapp-permissions-oplus.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/permissions/privapp-permissions-oplus.xml \
    $(OPLUS_CAMERA_PATH)/configs/framework/androidx.camera.extensions.impl.jar:$(TARGET_COPY_OUT_SYSTEM_EXT)/framework/androidx.camera.extensions.impl.jar \
    $(OPLUS_CAMERA_PATH)/configs/sysconfig/hiddenapi-package-oplus-whitelist.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/sysconfig/hiddenapi-package-oplus-whitelist.xml

# Gallery's ODNN retouch path dlopens QNN libraries by basename. Install the
# OP15 QNN runtime in system_ext and place real copies in Gallery's native lib dir.
PRODUCT_PACKAGES += \
    libQnnHtp_gallery_system_ext \
    libQnnHtpPrepare_gallery_system_ext \
    libQnnHtpV81Stub_gallery_system_ext \
    libQnnHtpV81CalculatorStub_gallery_system_ext \
    libQnnSaver_gallery_system_ext \
    libQnnSystem_gallery_system_ext \
    libQnnHtp_gallery_app_lib \
    libQnnHtpPrepare_gallery_app_lib \
    libQnnHtpV81Stub_gallery_app_lib \
    libQnnHtpV81CalculatorStub_gallery_app_lib \
    libQnnSaver_gallery_app_lib \
    libQnnSystem_gallery_app_lib \
    libNativeWinBuffExchange_camera_app_lib \
    libHeifEncoderWrapper_camera_app_lib \
    libHeifWinBufExchg-jni

# Properties
PRODUCT_PRODUCT_PROPERTIES += \
    persist.vendor.camera.privapp.list=com.oplus.camera,com.oneplus.gallery \
    persist.camera.override_enable=true \
    persist.camera.override_preview_hdr_support=false \
    persist.sys.feature.dolby_vision=1 \
    persist.sys.feature.dolby_vision_app=1 \
    persist.sys.feature.hdr_vision_app=1 \
    persist.sys.feature.localhdr_version=2 \
    persist.sys.feature.support.edrlistener=true \
    persist.sys.feature.uhdr.support=true \
    persist.sys.oplus.anim_level=1 \
    persist.sys.camera.private.log.enable=debug,pre,mp \
    ro.build.version.module.sub_api=2 \
    ro.build.version.oplus.api=38 \
    ro.build.version.oplus.sub_api=50 \
    ro.build.version.oplusrom=V16.1.0 \
    ro.build.version.oplusrom.display=16.0.10 \
    ro.build.version.oplusrom.confidential=V16.1.0 \
    ro.com.google.lens.oem_camera_package=com.oplus.camera \
    ro.com.google.lens.oem_image_package=com.oneplus.gallery,com.oplus.screenshot \
    ro.camerax.extensions.enabled=true \
    ro.oplus.fusionlight=true \
    ro.oplus.camera.defercap.support=1 \
    ro.oplus.system.gallery.name=com.oneplus.gallery \
    ro.oplus.system.camera.name=com.oplus.camera \
    ro.oplus.camera.defercap.all.quick.visible.support=1 \
    ro.oplus.camera.livephoto.support=1 \
    ro.camera.disableHeicUltraHDR=1 \
    ro.vendor.oplus.hdr.uniform=1 \
    ro.vendor.oplus.vendorxml.enable=1 \
    vendor.oplus.hdr.uniform.debug=1 \
    oplus.software.camera.10bit=1 \
    ro.camera.notify_nfc=1 \
    ro.oplus.camera.facing.front.need.disable.nfc=1 \
    ro.oplus.camera.portrait.center.switch=oplus.switch.portrait.center \
    ro.oplus.camera.portrait_center.prefix=oplus.portrait.center. \
    ro.oplus.camera.video.beauty.switch=oplus.switch.video.beauty \
    ro.oplus.camera.video_beauty.prefix=oplus.video.beauty. \
    ro.oplus.camera.speechassist=true \
    ro.oplus.system.camera.flashlight=com.oplus.motor.flashlight \
    ro.camera.privileged.3rdpartyApp=com.mediatek.expert.mtkcamhelper;com.aiunit.aon; \
    persist.logd.log.load.camerahalserver.lower_limit=1000 \
    persist.logd.log.load.camerahalserver.threshold=800000 \
    persist.logd.log.load.camerahalserver.upper_limit=3000 \
    persist.logd.log.load.com.oplus.camera.lower_limit=1000 \
    persist.logd.log.load.com.oplus.camera.threshold=800000 \
    persist.logd.log.load.com.oplus.camera.upper_limit=3000 \
    persist.logd.log.load.vendor.qti.camera.provider-service_64.lower_limit=500 \
    persist.logd.log.load.vendor.qti.camera.provider-service_64.threshold=400000 \
    persist.logd.log.load.vendor.qti.camera.provider-service_64.upper_limit=1500 \

PRODUCT_VENDOR_PROPERTIES += \
    ro.camera.enableCamera1MaxZsl=1 \
    ro.vendor.oplus.camera.backCamSize=50MP+50MP+50MP \
    ro.vendor.oplus.camera.frontCamSize=32MP

PRODUCT_SYSTEM_EXT_PROPERTIES += \
    ro.build.version.oplus.api=38 \
    ro.build.version.oplus.sub_api=50 \
    ro.vendor.oplus.vendorxml.enable=1

# Photo
$(call soong_config_set,camera,package_name,com.oplus.packageName)

# Video
$(call soong_config_set_bool,camera,override_format_from_reserved,true)

# SEpolicy
include device/oneplus/infiniti-camera/sepolicy/SEPolicy.mk

# Inherit from camera-vendor.mk
$(call inherit-product-if-exists, vendor/oneplus/infiniti-camera/infiniti-camera-vendor.mk)

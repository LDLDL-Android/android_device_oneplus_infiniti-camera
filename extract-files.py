#!/usr/bin/env -S PYTHONPATH=../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: 2016 The CyanogenMod Project
# SPDX-FileCopyrightText: 2017-2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

from extract_utils.fixups_lib import (
    lib_fixups,
    lib_fixups_user_type,
)
from extract_utils.fixups_blob import (
    apktool_path,
    blob_fixup,
    blob_fixups_user_type,
    java_path,
)
from extract_utils.main import (
    ExtractUtils,
    ExtractUtilsModule,
)
from extract_utils.utils import run_cmd
from hashlib import sha256
from pathlib import Path
import glob
import re
import shutil
import subprocess


APSCLIENT_STOCK_SHA256 = 'b6669463a2dbdc22d20d0bb1a565ef9f1cc058f5f34c627a8d49971f7c509bec'
APSCLIENT_PATCHED_SHA256 = 'fadd66bfe6344294fa0d3055382b1506e8432d01a562849478be82973e5974f8'
APSCLIENT_HEIF_DLOPEN_TARGETS = (
    (0x4C11B, b'libHeifEncoderWrapper.so', b'xibHeifEncoderWrapper.so'),
    (0x48551, b'libNativeWinBuffExchange.so', b'xibNativeWinBuffExchange.so'),
)


def lib_fixup_system_ext_suffix(lib: str, partition: str, *args, **kwargs):
    """
    Mirrors lib_to_package_fixup_system_ext_variants from the old setup-makefiles.sh.
    These libs exist as system_ext variants and need a _system_ext suffix
    when pulled from that partition.
    """
    if partition != 'system_ext':
        return None

    system_ext_libs = {
        'libSuperTextWrapper',
        'libXDocProcessSDK',
        'libYTCommon',
        'libmpbase',
        'libextendfile',
    }

    return f'{lib}_system_ext' if lib in system_ext_libs else None


def _noop_smali_method(data: str, signature: str) -> str:
    return re.sub(
        rf'(?ms)^\.method {re.escape(signature)}\n.*?^\.end method',
        f'.method {signature}\n'
        '    .locals 0\n'
        '\n'
        '    return-void\n'
        '.end method',
        data,
    )


def _replace_smali_method(data: str, signature: str, body: str) -> str:
    return re.sub(
        rf'(?ms)^\.method {re.escape(signature)}\n.*?^\.end method',
        f'.method {signature}\n{body}.end method',
        data,
    )


def _empty_map_smali_body() -> str:
    return (
        '    .locals 1\n'
        '\n'
        '    invoke-static {}, Ljava/util/Collections;->emptyMap()Ljava/util/Map;\n'
        '\n'
        '    move-result-object v0\n'
        '\n'
        '    return-object v0\n'
    )


def blob_fixup_apktool_unpack_src(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    run_cmd([
        java_path,
        '-Xmx8g',
        '-jar',
        apktool_path,
        'd',
        file_path,
        '-o',
        tmp_dir,
        '-f',
        '--no-res',
    ])


def blob_fixup_apktool_unpack_full(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    run_cmd([
        java_path,
        '-Xmx8g',
        '-jar',
        apktool_path,
        'd',
        file_path,
        '-o',
        tmp_dir,
        '-f',
    ])


def blob_fixup_apktool_unpack_manifest(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    run_cmd([
        java_path,
        '-Xmx8g',
        '-jar',
        apktool_path,
        'd',
        file_path,
        '-o',
        tmp_dir,
        '-f',
        '-s',
    ])


def blob_fixup_opluscamera_font(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # OEM camera font-NPE neutralizer. The TypeFaceUtil static
    # (Context)->Typeface getFontTypeface path (16.0.8/16.0.10: a(Context))
    # reads OEM font framework state (OplusBaseConfiguration
    # mFontVariationSettings) that is absent on LineageOS; return
    # Typeface.DEFAULT instead. Located by source file + OEM field anchor, not
    # by the obfuscated class/method name.
    if tmp_dir is None:
        return

    method_re = re.compile(
        r'(?ms)^\.method (public static [\w$]+\(Landroid/content/Context;\)Landroid/graphics/Typeface;)\n'
        r'.*?^\.end method'
    )
    anchor = 'Loplus/content/res/OplusExtraConfiguration;->mFontVariationSettings:I'
    body = (
        '    .locals 1\n'
        '\n'
        '    sget-object v0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;\n'
        '\n'
        '    return-object v0\n'
    )

    targets = []
    already = False
    for smali in _grep_smali(tmp_dir, '.source "TypeFaceUtil.java"'):
        data = smali.read_text(encoding='utf-8', errors='ignore')
        for m in method_re.finditer(data):
            if anchor in m.group(0):
                targets.append((smali, m.group(1)))
            elif m.group(0) == f'.method {m.group(1)}\n{body}.end method':
                already = True
    if len(targets) > 1:
        raise ValueError('OplusCamera TypeFaceUtil font typeface method is ambiguous')
    if not targets:
        if already:
            return
        raise ValueError('OplusCamera TypeFaceUtil font typeface method not found')

    smali, signature = targets[0]
    data = smali.read_text(encoding='utf-8', errors='ignore')
    smali.write_text(_replace_smali_method(data, signature, body), encoding='utf-8')


_BLUR_SEGINIT_CALL = (
    r'invoke-virtual/range \{v\d+ \.\. v\d+\}, '
    r'Lcom/oplus/ocs/camera/OplusBlurPreviewHelper;->segInit\('
    r'Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II\)\[I'
)
# segInit(...) result -> move-result-object R -> sput-object R, L<process>;-><field>:[I
_BLUR_SEGINIT_WRITE_RE = re.compile(
    rf'{_BLUR_SEGINIT_CALL}'
    r'(?:\s+\.line \d+)*\s+'
    r'move-result-object ([vp]\d+)'
    r'(?:\s+\.line \d+)*\s+'
    r'sput-object \1, L[^;\s]+;->[\w$]+:\[I'
)


def _smali_methods(data: str):
    return re.finditer(r'(?ms)^\.method [^\n]*\n.*?^\.end method\n?', data)


def _blur_find_seginit_method(tmp_dir, required, method_filter, what):
    # Locate the (obfuscated) method by surviving strings + the segInit API
    # call, never by class/method name.
    for smali in Path(tmp_dir).glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8', errors='ignore')
        if 'OplusBlurPreviewHelper;->segInit(' not in data or not all(r in data for r in required):
            continue
        for m in _smali_methods(data):
            body = m.group(0)
            if 'OplusBlurPreviewHelper;->segInit(' in body and all(r in body for r in required) \
                    and method_filter(body):
                return smali, data, m
    raise ValueError(f'OplusCamera {what} segInit anchor not found')


def blob_fixup_opluscamera_blur_seginit_guard(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Portrait blur initialization can fail when the OEM segmentation stack is
    # incomplete. The app normally dereferences the returned int[] without a
    # null check, crashing on front-camera portrait. Treat a null segInit()
    # result as an unavailable blur engine instead.
    #
    # Two call sites (16.0.8: ub/b + wb/k, 16.0.10: xb/b + zb/l), found by
    # stable strings/framework calls rather than obfuscated names:
    #  - OplusBlurProcess static synchronized initialize(II)Z: on null, exit
    #    the class monitor and return false.
    #  - initSegForSizeChange(II)V: on null, return early.
    if tmp_dir is None:
        return

    # 1) OplusBlurProcess.initialize
    marker = ':cond_codex_blur_seginit_ok'
    smali, data, m = _blur_find_seginit_method(
        tmp_dir,
        ('"/odm/etc/camera/singleblur/personseg.bin"', '"initialize, init Result: "'),
        lambda body: re.search(r'(?m)^\.method [^\n]*\)Z$', body) and 'monitor-enter' in body,
        'blur process',
    )
    method = m.group(0)
    if marker not in method:
        monitors = set(re.findall(r'(?m)^\s+monitor-enter ([vp]\d+)$', method))
        if len(monitors) != 1:
            raise ValueError('OplusCamera blur process monitor register not found')
        monitor = monitors.pop()
        fixed, count = _BLUR_SEGINIT_WRITE_RE.subn(
            lambda w: w.group(0) + (
                '\n\n'
                f'    if-nez {w.group(1)}, {marker}\n'
                '\n'
                f'    monitor-exit {monitor}\n'
                '\n'
                f'    const/16 {w.group(1)}, 0x0\n'
                '\n'
                f'    return {w.group(1)}\n'
                '\n'
                f'    {marker}'
            ),
            method,
            count=1,
        )
        if count != 1:
            raise ValueError('OplusCamera blur process segInit write not patched')
        data = data[:m.start()] + fixed + data[m.end():]
        smali.write_text(data, encoding='utf-8')

    # 2) initSegForSizeChange
    marker = ':cond_codex_blur_size_seginit_ok'
    smali, data, m = _blur_find_seginit_method(
        tmp_dir,
        ('"initSegForSizeChange, segInit, cost: "',),
        lambda body: re.search(r'(?m)^\.method [^\n]*\)V$', body),
        'blur size-change',
    )
    method = m.group(0)
    if marker not in method:
        fixed, count = _BLUR_SEGINIT_WRITE_RE.subn(
            lambda w: w.group(0) + (
                '\n\n'
                f'    if-nez {w.group(1)}, {marker}\n'
                '\n'
                '    return-void\n'
                '\n'
                f'    {marker}'
            ),
            method,
            count=1,
        )
        if count != 1:
            raise ValueError('OplusCamera blur size-change segInit write not patched')
        data = data[:m.start()] + fixed + data[m.end():]
        smali.write_text(data, encoding='utf-8')


def blob_fixup_strip_oem_permissions(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Strip undefined OEM permission gates from component declarations while
    # keeping the components registered.
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    if not manifest.exists():
        return

    data = manifest.read_text(encoding='utf-8')
    fixed = re.sub(
        r'\s+android:permission="(?:oplus|oppo|com\.oplus|com\.oppo|com\.heytap)[^"]*"',
        '',
        data,
    )
    if fixed != data:
        manifest.write_text(fixed, encoding='utf-8')


_SEEDLING_CONTEXT_HANDLER = 'Lcom/oplus/systemui/plugins/seedling/plugin/ContextHandler;'


def _smali_param_reg_count(method_header: str) -> int:
    params = re.search(r'\((.*?)\)', method_header).group(1)
    count = 0 if ' static ' in f' {method_header} ' else 1
    for t in re.findall(r'\[*(?:L[^;]+;|[ZBSCIFJD])', params):
        count += 2 if t in ('J', 'D') else 1
    return count


def blob_fixup_systemuiplugin_plugin_context_inflater(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # The seedling card-root window manager (16.0.8: t4/h, 16.0.10: l5/h) is a
    # singleton built from whatever Context its first caller passes (often the
    # SystemUI host context), and the card root ViewGroup is constructed with
    # the SystemUI context while its layout comes from the plugin APK. Make the
    # singleton use the plugin context from ContextHandler.getPluginCtx() and
    # build/inflate the card root with that plugin context.
    #
    # Anchors (no obfuscated names): ContextHandler.getSysUiCtx() followed by
    # the seedling_card_root View.inflate() call, then the
    # (Context)L<manager>; double-checked singleton getter.
    if tmp_dir is None:
        return

    root = Path(tmp_dir)
    layout_id = None
    public_xml = root / 'res' / 'values' / 'public.xml'
    if public_xml.exists():
        lm = re.search(
            r'<public type="layout" name="seedling_card_root" id="(0x[0-9a-f]+)"',
            public_xml.read_text(encoding='utf-8', errors='ignore'),
        )
        layout_id = lm.group(1) if lm else None
    if layout_id is None:
        raise ValueError('SystemUIPlugin seedling_card_root layout id not found')

    inflate_call = (
        'Landroid/view/View;->inflate(Landroid/content/Context;ILandroid/view/ViewGroup;)'
        'Landroid/view/View;'
    )
    inflater_call = 'Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;'
    card_root_re = re.compile(
        r'new-instance (?P<view>[vp]\d+), (?P<cls>L[^;\s]+;)\s+'
        r'invoke-direct \{(?P=view), (?P<sysui>[vp]\d+)\}, (?P=cls)-><init>\(Landroid/content/Context;\)V\s+'
        r'iget-object (?P<ctx>[vp]\d+), p0, (?P<mgr>L[^;\s]+;)->(?P<field>[\w$]+):Landroid/content/Context;\s+'
        rf'const (?P<id>[vp]\d+), {layout_id}\s+'
        rf'invoke-static \{{(?P=ctx), (?P=id), (?P=view)\}}, {re.escape(inflate_call)}'
    )
    patched_re = re.compile(
        r'iget-object (?P<ctx>[vp]\d+), p0, (?P<mgr>L[^;\s]+;)->[\w$]+:Landroid/content/Context;\s+'
        r'new-instance [vp]\d+, L[^;\s]+;\s+'
        r'invoke-direct \{[vp]\d+, (?P=ctx)\}, L[^;\s]+;-><init>\(Landroid/content/Context;\)V\s+'
        rf'const [vp]\d+, {layout_id}\s+'
        r'invoke-static \{(?P=ctx)\}, Landroid/view/LayoutInflater;->from'
    )

    mgr = None
    for smali in root.glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8', errors='ignore')
        if layout_id not in data or f'{_SEEDLING_CONTEXT_HANDLER}->getSysUiCtx()' not in data:
            continue
        for m in _smali_methods(data):
            method = m.group(0)
            pm = patched_re.search(method)
            if pm:
                mgr = pm.group('mgr')
                break
            cm = card_root_re.search(method)
            if cm is None:
                continue
            mgr = cm.group('mgr')
            header = method.split('\n', 1)[0]
            lm = re.search(r'(?m)^    \.locals (\d+)$', method)
            if lm is None:
                raise ValueError('SystemUIPlugin card root method has no .locals')
            locals_count = int(lm.group(1))
            inflater, attach = f'v{locals_count}', f'v{locals_count + 1}'
            # invoke-virtual/iget use 4-bit registers; keep every register,
            # including the shifted p-registers, addressable.
            if locals_count + 2 + _smali_param_reg_count(header) > 16:
                raise ValueError('SystemUIPlugin card root method has no spare low registers')
            view, ctx_reg, id_reg = cm.group('view'), cm.group('ctx'), cm.group('id')
            replacement = (
                f'iget-object {ctx_reg}, p0, {mgr}->{cm.group("field")}:Landroid/content/Context;\n'
                '\n'
                f'    new-instance {view}, {cm.group("cls")}\n'
                '\n'
                f'    invoke-direct {{{view}, {ctx_reg}}}, {cm.group("cls")}-><init>(Landroid/content/Context;)V\n'
                '\n'
                f'    const {id_reg}, {layout_id}\n'
                '\n'
                f'    invoke-static {{{ctx_reg}}}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;\n'
                '\n'
                f'    move-result-object {inflater}\n'
                '\n'
                f'    const/4 {attach}, 0x1\n'
                '\n'
                f'    invoke-virtual {{{inflater}, {id_reg}, {view}, {attach}}}, {inflater_call}'
            )
            method = method[:cm.start()] + replacement + method[cm.end():]
            method = method[:lm.start()] + f'    .locals {locals_count + 2}' + method[lm.end():]
            data = data[:m.start()] + method + data[m.end():]
            smali.write_text(data, encoding='utf-8')
            break
        if mgr is not None:
            break
    if mgr is None:
        raise ValueError('SystemUIPlugin seedling card root inflate anchor not found')

    getter_re = re.compile(
        r'(?P<new>new-instance (?P<reg>[vp]\d+), ' + re.escape(mgr) + r'\s+'
        r'invoke-direct \{(?P=reg), (?P<ctx>[vp]\d+)\}, ' + re.escape(mgr)
        + r'-><init>\(Landroid/content/Context;\)V)'
    )
    getter_sig = re.compile(
        r'(?m)^\.method [^\n]*\(Landroid/content/Context;\)' + re.escape(mgr) + '$'
    )
    patched_getter = False
    for smali in root.glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8', errors='ignore')
        if f'{mgr}-><init>(Landroid/content/Context;)V' not in data:
            continue
        for m in _smali_methods(data):
            method = m.group(0)
            if not getter_sig.search(method) or 'monitor-enter' not in method:
                continue
            if f'{_SEEDLING_CONTEXT_HANDLER}->getPluginCtx()' in method:
                patched_getter = True
                break
            gm = getter_re.search(method)
            if gm is None:
                continue
            reg, ctx_reg = gm.group('reg'), gm.group('ctx')
            prefix = (
                f'sget-object {reg}, {_SEEDLING_CONTEXT_HANDLER}->Companion:'
                f'{_SEEDLING_CONTEXT_HANDLER[:-1]}$Companion;\n'
                '\n'
                f'    invoke-virtual {{{reg}}}, {_SEEDLING_CONTEXT_HANDLER[:-1]}$Companion;->getInstance()'
                f'{_SEEDLING_CONTEXT_HANDLER}\n'
                '\n'
                f'    move-result-object {reg}\n'
                '\n'
                f'    invoke-virtual {{{reg}}}, {_SEEDLING_CONTEXT_HANDLER}->getPluginCtx()Landroid/content/Context;\n'
                '\n'
                f'    move-result-object {reg}\n'
                '\n'
                f'    if-eqz {reg}, :cond_codex_plugin_ctx_fallback\n'
                '\n'
                f'    move-object {ctx_reg}, {reg}\n'
                '\n'
                '    :cond_codex_plugin_ctx_fallback\n'
                '    '
            )
            method = method[:gm.start()] + prefix + gm.group('new') + method[gm.end():]
            data = data[:m.start()] + method + data[m.end():]
            smali.write_text(data, encoding='utf-8')
            patched_getter = True
            break
        if patched_getter:
            break
    if not patched_getter:
        raise ValueError(f'SystemUIPlugin {mgr} singleton getter anchor not found')


def blob_fixup_opluscamera_oppo_component_safe(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    permission = '    <uses-permission android:name="oppo.permission.OPPO_COMPONENT_SAFE"/>\n'
    if 'oppo.permission.OPPO_COMPONENT_SAFE' not in data:
        data = data.replace(
            '    <uses-permission android:name="oplus.permission.OPLUS_COMPONENT_SAFE"/>\n',
            '    <uses-permission android:name="oplus.permission.OPLUS_COMPONENT_SAFE"/>\n'
            + permission,
            1,
        )
        manifest.write_text(data, encoding='utf-8')


def blob_fixup_opluscamera_uses_library(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    if not data or 'oplus.camera.stubs' in data:
        return

    entry = '        <uses-library android:name="oplus.camera.stubs" android:required="false"/>\n'
    sdk_entry = '        <uses-library android:name="com.oplus.camera.unit.sdk" android:required="false"/>\n'
    if sdk_entry in data:
        data = data.replace(sdk_entry, entry + sdk_entry, 1)
        manifest.write_text(data, encoding='utf-8')
    elif '</application>' in data:
        data = data.replace('</application>', entry + '    </application>', 1)
        manifest.write_text(data, encoding='utf-8')


def blob_fixup_fileencryption_secure_settings_permission(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    permissions = (
        'android.permission.USE_BIOMETRIC',
        'android.permission.USE_FINGERPRINT',
        'android.permission.WRITE_SECURE_SETTINGS',
    )
    entries = ''.join(
        f'    <uses-permission android:name="{permission}"/>\n'
        for permission in permissions
        if permission not in data
    )
    if data and entries:
        data = data.replace('<application ', entries + '    <application ', 1)
        manifest.write_text(data, encoding='utf-8')


def blob_fixup_fileencryption_biometric_enrollment_checks(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # BiometricsUnlockManager's "has enrolled face/fingerprint" helpers go
    # through OplusFaceManager / Oplus fingerprint wrappers / Epona, none of
    # which work here; replace them with AOSP FaceManager/FingerprintManager.
    # The class was c9/a (methods b/c) on 16.0.8 and v9/a (c/d) on 16.0.10, so
    # find it by its Kotlin source name and the methods by their contents.
    if tmp_dir is None:
        return

    smali = None
    for candidate in Path(tmp_dir).glob('smali*/**/*.smali'):
        with candidate.open(encoding='utf-8', errors='ignore') as f:
            header = f.read(512)
        if '.source "BiometricsUnlockManager.kt"' in header:
            smali = candidate
            break
    data = smali.read_text(encoding='utf-8') if smali is not None else ''
    if not data:
        raise ValueError('FileEncryption biometric helper not found')

    face_body = (
        '    .locals 2\n'
        '\n'
        '    :try_start_0\n'
        '    const-string v0, "face"\n'
        '\n'
        '    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;\n'
        '\n'
        '    move-result-object p0\n'
        '\n'
        '    instance-of v0, p0, Landroid/hardware/face/FaceManager;\n'
        '\n'
        '    if-eqz v0, :cond_0\n'
        '\n'
        '    check-cast p0, Landroid/hardware/face/FaceManager;\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/hardware/face/FaceManager;->hasEnrolledTemplates()Z\n'
        '\n'
        '    move-result p0\n'
        '\n'
        '    return p0\n'
        '    :try_end_0\n'
        '    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0\n'
        '\n'
        '    :catch_0\n'
        '    move-exception p0\n'
        '\n'
        '    :cond_0\n'
        '    const/4 p0, 0x0\n'
        '\n'
        '    return p0\n'
    )
    fingerprint_body = (
        '    .locals 2\n'
        '\n'
        '    :try_start_0\n'
        '    const-string v0, "fingerprint"\n'
        '\n'
        '    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;\n'
        '\n'
        '    move-result-object p0\n'
        '\n'
        '    instance-of v0, p0, Landroid/hardware/fingerprint/FingerprintManager;\n'
        '\n'
        '    if-eqz v0, :cond_0\n'
        '\n'
        '    check-cast p0, Landroid/hardware/fingerprint/FingerprintManager;\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/hardware/fingerprint/FingerprintManager;->isHardwareDetected()Z\n'
        '\n'
        '    move-result v0\n'
        '\n'
        '    if-eqz v0, :cond_0\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/hardware/fingerprint/FingerprintManager;->hasEnrolledFingerprints()Z\n'
        '\n'
        '    move-result p0\n'
        '\n'
        '    return p0\n'
        '    :try_end_0\n'
        '    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0\n'
        '\n'
        '    :catch_0\n'
        '    move-exception p0\n'
        '\n'
        '    :cond_0\n'
        '    const/4 p0, 0x0\n'
        '\n'
        '    return p0\n'
    )
    method_re = re.compile(
        r'(?ms)^\.method (?P<sig>public static final \w+\(Landroid/content/Context;\)Z)\n(?P<body>.*?)^\.end method'
    )
    face_sigs, fingerprint_sigs = [], []
    face_done = fingerprint_done = False
    for method in method_re.finditer(data):
        sig, body = method.group('sig', 'body')
        if body == face_body:
            face_done = True
        elif body == fingerprint_body:
            fingerprint_done = True
        elif '"android.hardware.face.FaceManager"' in body and 'hasEnrolledTemplates' in body:
            face_sigs.append(sig)
        elif re.search(r'const-string [vp]\d+, "fingerprint"\n', body) and 'getSystemService' in body:
            fingerprint_sigs.append(sig)

    fixed = data
    for kind, sigs, done, body in (
        ('face', face_sigs, face_done, face_body),
        ('fingerprint', fingerprint_sigs, fingerprint_done, fingerprint_body),
    ):
        if done and not sigs:
            continue
        if len(sigs) != 1:
            raise ValueError(
                f'FileEncryption biometric enrollment checks not patched: '
                f'{len(sigs)} {kind} enrollment candidates'
            )
        fixed = _replace_smali_method(fixed, sigs[0], body)
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_phonemanager_secure_settings_permission(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    permission = '    <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"/>\n'
    if data and 'android.permission.WRITE_SECURE_SETTINGS' not in data:
        data = data.replace('<application ', permission + '    <application ', 1)
        manifest.write_text(data, encoding='utf-8')


def blob_fixup_ums_activity_watcher_permission(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    permission = '    <uses-permission android:name="android.permission.SET_ACTIVITY_WATCHER"/>\n'
    if data and 'android.permission.SET_ACTIVITY_WATCHER' not in data:
        data = data.replace('<application ', permission + '    <application ', 1)
        manifest.write_text(data, encoding='utf-8')


def blob_fixup_phonemanager_settings_category(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    if not data:
        return

    old = 'android:value="com.oplus.settings.category.ia.phone_manager"'
    new = 'android:value="com.android.settings.category.ia.more_security_privacy_settings"'
    fixed = data.replace(old, new, 1)
    if fixed != data:
        manifest.write_text(fixed, encoding='utf-8')
    elif new not in data:
        raise ValueError('PhoneManager Settings category metadata not found')


_SETTINGS_CATEGORY_ADVANCED_SECURITY_META = (
    '<meta-data android:name="com.android.settings.category" '
    'android:value="com.android.settings.category.ia.advanced_security"/>'
)


def blob_fixup_aonservice_settings_category(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # AONService's EZ Pay tile declares MANUFACTURER_APPLICATION_SETTING without
    # an AOSP Settings category, so TileUtils can surface it on unrelated pages.
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    if not data or _SETTINGS_CATEGORY_ADVANCED_SECURITY_META in data:
        return

    anchor = (
        '<meta-data android:name="com.android.settings.title" '
        'android:resource="@string/intelligent_perception_title_new"/>'
    )
    if anchor not in data:
        raise ValueError('AONService Settings title metadata not found')

    manifest.write_text(
        data.replace(anchor, anchor + '\n            ' + _SETTINGS_CATEGORY_ADVANCED_SECURITY_META, 1),
        encoding='utf-8',
    )


def blob_fixup_aiunit_settings_category(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # AIUnit's AI Service Engine tile uses the Oplus-only
    # com.android.settings.category.export key, which AOSP TileUtils ignores.
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    if not data or _SETTINGS_CATEGORY_ADVANCED_SECURITY_META in data:
        return

    old = (
        '<meta-data android:name="com.android.settings.category.export" '
        'android:value="com.oplus.settings.category.ia.strengthen_service"/>'
    )
    if old not in data:
        raise ValueError('AIUnit Settings category metadata not found')

    manifest.write_text(data.replace(old, _SETTINGS_CATEGORY_ADVANCED_SECURITY_META, 1), encoding='utf-8')


def blob_fixup_aiunit_settings_search(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # AIUnit portion of lighthouse-camera commit 957ac7388e3923009ff81ca444091db920eb988a.
    # Google Settings Intelligence requires an unqualified PreferenceScreen root;
    # AndroidX's inflater still resolves it to androidx.preference.PreferenceScreen.
    if tmp_dir is None:
        return

    preference_xml = Path(tmp_dir) / 'res/xml/fragment_ai_service_platform.xml'
    data = preference_xml.read_text(encoding='utf-8') if preference_xml.exists() else ''
    if not data:
        raise ValueError('AIUnit AI Service Engine preference XML not found')

    old_open = '<androidx.preference.PreferenceScreen'
    old_close = '</androidx.preference.PreferenceScreen>'
    new_open = '<PreferenceScreen'
    new_close = '</PreferenceScreen>'

    if old_open not in data or old_close not in data:
        if new_open in data and new_close in data:
            return
        raise ValueError('AIUnit AI Service Engine PreferenceScreen root not found')

    preference_xml.write_text(
        data.replace(old_open, new_open, 1).replace(old_close, new_close, 1),
        encoding='utf-8',
    )


def blob_fixup_phonemanager_permission_controller_package(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    old = 'com.google.android.permissioncontroller'
    new = 'com.android.permissioncontroller'
    replaced = False
    for path in Path(tmp_dir).glob('**/*'):
        if not path.is_file() or path.suffix not in {'.smali', '.xml'}:
            continue
        data = path.read_text(encoding='utf-8', errors='ignore')
        if old not in data:
            continue
        path.write_text(data.replace(old, new), encoding='utf-8')
        replaced = True

    if not replaced:
        raise ValueError('PhoneManager permission controller package string not found')


def blob_fixup_cryptoeng_permissions_xml(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    path = Path(file_path)
    data = path.read_text(encoding='utf-8')
    fixed = data.replace('\n</permissions>\n\n<permissions>\n', '\n')
    if fixed != data:
        path.write_text(fixed, encoding='utf-8')


def blob_fixup_cryptoeng_init_rc(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    path = Path(file_path)
    data = path.read_text(encoding='utf-8')
    data = data.replace(
        '    mkdir /data/vendor_de/0/cryptoeng 0770 system system encryption=None\n',
        '    mkdir /data/vendor_de/0/cryptoeng 0770 system system encryption=None\n'
        '    restorecon_recursive /data/vendor_de/0/cryptoeng\n',
        1,
    )
    old = (
        '    if [ "$(getprop ro.soc.model)" = "SM6450" ]; then\n'
        '        copy /vendor/etc/oplus_PPID_licenses.pfm /mnt/vendor/persist/data/pfm/licenses/oplus_PPID_licenses.pfm\n'
        '        chmod 0600 /mnt/vendor/persist/data/pfm/licenses/oplus_PPID_licenses.pfm\n'
        '        chown system system /mnt/vendor/persist/data/pfm/licenses/oplus_PPID_licenses.pfm\n'
        '    fi\n'
    )
    fixed = data.replace(old, '')
    if fixed != data:
        path.write_text(fixed, encoding='utf-8')


def blob_fixup_cryptoeng_manifest(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    path = Path(file_path)
    data = path.read_text(encoding='utf-8')
    data = data.replace('<!--\n    <hal format="hidl">', '    <hal format="hidl">')
    data = data.replace('    </hal>\n-->\n    <hal format="aidl">', '    </hal>\n    <hal format="aidl">')
    path.write_text(data, encoding='utf-8')


_REGISTER_RECEIVER_4 = (
    'Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;'
    'Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;'
)
_REGISTER_RECEIVER_5 = (
    'Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;'
    'Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;'
)


def blob_fixup_safecenter_receiver_flags(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # BaseSelfFinishActivity registers a dynamic receiver without
    # RECEIVER_EXPORTED/RECEIVER_NOT_EXPORTED, which throws on targetSdk >= 34.
    # Rewrite the call to the flags overload with RECEIVER_NOT_EXPORTED (0x4).
    # 16.0.8 kept the class in smali_classes2, 16.0.10 moved it to smali, so
    # look it up by its (unobfuscated) class path in any dex.
    if tmp_dir is None:
        return

    smali = next(
        Path(tmp_dir).glob('smali*/com/oplus/safecenter/privacy/view/BaseSelfFinishActivity.smali'), None
    )
    if smali is None:
        raise ValueError('SafeCenter BaseSelfFinishActivity smali not found')
    data = smali.read_text(encoding='utf-8')

    method_re = re.compile(
        r'(?ms)^\.method protected onCreate\(Landroid/os/Bundle;\)V\n.*?^\.end method'
    )
    method = method_re.search(data)
    if method is None:
        raise ValueError('SafeCenter BaseSelfFinishActivity.onCreate not found')
    body = method.group(0)

    call_re = re.compile(
        r'^(?P<indent>[ \t]*)invoke-virtual \{(?P<regs>(?:[vp]\d+, ){4}[vp]\d+)\}, '
        + re.escape(_REGISTER_RECEIVER_4) + r'\n',
        re.M,
    )
    calls = list(call_re.finditer(body))
    if not calls:
        if _REGISTER_RECEIVER_5 in body:
            return
        raise ValueError('SafeCenter receiver flag patch point not found')
    if len(calls) != 1:
        raise ValueError(f'SafeCenter receiver flag patch point ambiguous ({len(calls)} matches)')

    locals_match = re.search(r'^    \.locals (\d+)\n', body, re.M)
    if locals_match is None:
        raise ValueError('SafeCenter BaseSelfFinishActivity.onCreate .locals not found')
    base = int(locals_match.group(1))

    call = calls[0]
    indent = call.group('indent')
    regs = call.group('regs').split(', ')
    tmp = [f'v{base + i}' for i in range(5)]
    replacement = ''.join(
        f'{indent}move-object/from16 {dst}, {src}\n\n' for dst, src in zip(tmp, regs)
    )
    replacement += (
        f'{indent}const/16 v{base + 5}, 0x4\n\n'
        f'{indent}invoke-virtual/range {{v{base} .. v{base + 5}}}, {_REGISTER_RECEIVER_5}\n'
    )
    new_body = body[:call.start()] + replacement + body[call.end():]
    new_body = (
        new_body[:locals_match.start()]
        + f'    .locals {base + 6}\n'
        + new_body[locals_match.end():]
    )
    smali.write_text(data[:method.start()] + new_body + data[method.end():], encoding='utf-8')


_SAFECENTER_OLOCK_FORCED_LOG = '[isSupportOLock] force enabled for port'


def blob_fixup_safecenter_olock_support(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Force OLockManager.isSupportOLock(Context) to return true. 16.0.8 had it
    # as j7/k->J with logger x6/a->h; 16.0.10 renamed both, so locate the
    # method by its "[isSupportOLock] isSupport:false" log string and reuse
    # whichever logger it calls with that message.
    if tmp_dir is None:
        return

    anchor = '"[isSupportOLock] isSupport:false"'
    method_re = re.compile(
        r'(?ms)^\.method (?P<sig>public final \w+\(Landroid/content/Context;\)Z)\n(?P<body>.*?)^\.end method'
    )
    targets = []
    for smali in Path(tmp_dir).glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8', errors='ignore')
        if 'isSupportOLock' not in data:
            continue
        if _SAFECENTER_OLOCK_FORCED_LOG in data:
            return
        for method in method_re.finditer(data):
            if anchor in method.group('body'):
                targets.append((smali, data, method))
    if len(targets) != 1:
        raise ValueError(
            f'SafeCenter OLock support patch point not found ({len(targets)} isSupportOLock candidates)'
        )

    smali, data, method = targets[0]
    logger = re.search(
        r'const-string (?P<msg>[vp]\d+), ' + re.escape(anchor) + r'\n\s*'
        r'invoke-static \{(?P<tag>[vp]\d+), (?P=msg)\}, '
        r'(?P<fn>L[^;]+;->\w+\(Ljava/lang/String;Ljava/lang/String;\)V)\n',
        method.group('body'),
    )
    if logger is None:
        raise ValueError('SafeCenter OLock support logger call not found')

    fixed = _replace_smali_method(
        data,
        method.group('sig'),
        '    .locals 2\n'
        '\n'
        '    const-string p0, "OLockManager"\n'
        '\n'
        f'    const-string p1, "{_SAFECENTER_OLOCK_FORCED_LOG}"\n'
        '\n'
        f'    invoke-static {{p0, p1}}, {logger.group("fn")}\n'
        '\n'
        '    const/4 v0, 0x1\n'
        '\n'
        '    return v0\n',
    )
    if fixed == data:
        raise ValueError('SafeCenter OLock support patch point not found')
    smali.write_text(fixed, encoding='utf-8')


def blob_fixup_safecenter_olock_theft_dark_theme(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    values_night = Path(tmp_dir) / 'res/values-night/styles.xml'
    data = values_night.read_text(encoding='utf-8') if values_night.exists() else ''
    style = (
        '    <style name="AppTheme.OlockSettingTheme" parent="@style/Theme.COUI.Dark">\n'
        '        <item name="android:windowBackground">?couiColorBackgroundWithCard</item>\n'
        '        <item name="android:statusBarColor">?couiColorBackgroundWithCard</item>\n'
        '        <item name="android:navigationBarColor">?couiColorBackgroundWithCard</item>\n'
        '        <item name="android:isLightTheme">false</item>\n'
        '        <item name="android:windowDisablePreview">true</item>\n'
        '        <item name="enableFollowSystemForceDarkRank">true</item>\n'
        '        <item name="preferenceTheme">@style/PreferenceThemeOverlay.COUITheme</item>\n'
        '        <item name="viewInflaterClass">@string/coui_view_inflater_class</item>\n'
        '        <item name="windowActionBar">false</item>\n'
        '        <item name="windowNoTitle">true</item>\n'
        '        <item name="windowPreviewType">0</item>\n'
        '    </style>\n'
    )
    if 'name="AppTheme.OlockSettingTheme"' not in data:
        fixed = data.replace('    <style name="Theme.AppCompat.DayNight"', style + '    <style name="Theme.AppCompat.DayNight"', 1)
        if fixed == data:
            raise ValueError('SafeCenter OLock night theme patch point not found')
        values_night.write_text(fixed, encoding='utf-8')



def blob_fixup_securitypermission_safe_permissions(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8')
    permissions = [
        'oplus.permission.OPLUS_COMPONENT_SAFE',
        'oppo.permission.OPPO_COMPONENT_SAFE',
        'com.oplus.permission.safe.AI_APP',
        'com.oplus.permission.safe.APP_MANAGER',
        'com.oplus.permission.safe.ASSISTANT',
        'com.oplus.permission.safe.AUTHENTICATE',
        'com.oplus.permission.safe.BACKUP',
        'com.oplus.permission.safe.BLUETOOTH',
        'com.oplus.permission.safe.CAMERA',
        'com.oplus.permission.safe.CAR_LINK',
        'com.oplus.permission.safe.CONNECTIVITY',
        'com.oplus.permission.safe.IOT',
        'com.oplus.permission.safe.LOG',
        'com.oplus.permission.safe.MEDIA',
        'com.oplus.permission.safe.PERSISTENT',
        'com.oplus.permission.safe.PHONE',
        'com.oplus.permission.safe.PICTURE',
        'com.oplus.permission.safe.POWER',
        'com.oplus.permission.safe.PRIVATE',
        'com.oplus.permission.safe.PROTECT',
        'com.oplus.permission.safe.READ_COMMON',
        'com.oplus.permission.safe.SAFE_MANAGER',
        'com.oplus.permission.safe.SAU',
        'com.oplus.permission.safe.SECURITY',
        'com.oplus.permission.safe.SETTINGS',
        'com.oplus.permission.safe.SETTINGS_SEARCH',
        'com.oplus.permission.safe.WINDOW',
        'com.oppo.permission.safe.AI_APP',
        'com.oppo.permission.safe.AUTHENTICATE',
        'com.oppo.permission.safe.CAMERA',
        'com.oppo.permission.safe.IOT',
        'com.oppo.permission.safe.PRIVATE',
        'com.oppo.permission.safe.SAU',
        'com.oppo.permission.safe.SECURITY',
        'oplus.permission.settings.LAUNCH_FOR_EXPORT',
        'com.oplus.metis.factdata.permission.DATABASE',
        'com.oplus.flashback.permission.FLASH_VIEWS_SERVICE',
        'heytap.speechassist.permission.ACTIVATE_SPEECH_ASSIST',
    ]
    block = ''.join(
        f'    <permission android:name="{permission}" android:protectionLevel="signature|privileged" />\n'
        for permission in permissions
        if f'<permission android:name="{permission}"' not in data
    )
    if block:
        data = data.replace('<application ', block + '\n    <application ', 1)
        manifest.write_text(data, encoding='utf-8')


_SMALI_GAP = r'(?:\n|    \.line \d+\n)*'
_SMALI_METHOD_RE = re.compile(r'(?ms)^\.method [^\n]*\n.*?^\.end method\n?')


def _grep_smali(tmp_dir, needle: str) -> list:
    """Return smali files under tmp_dir that contain the literal needle."""
    result = subprocess.run(
        ['grep', '-rlF', '--include=*.smali', '--', needle, str(tmp_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode not in (0, 1):
        raise ValueError(f'grep failed while searching smali for {needle!r}')
    return sorted(Path(p) for p in result.stdout.splitlines() if p)


def _smali_class_file(tmp_dir, descriptor: str):
    rel = descriptor[1:-1] + '.smali'
    return next(iter(sorted(Path(tmp_dir).glob(f'smali*/{rel}'))), None)


def _smali_class_name(data: str) -> str:
    return re.search(r'^\.class [^\n]*?(L[^;\s]+;)$', data, re.M).group(1)


def _smali_set_min_locals(method: str, count: int) -> str:
    return re.sub(
        r'^(    \.locals )(\d+)$',
        lambda m: m.group(1) + str(max(int(m.group(2)), count)),
        method,
        count=1,
        flags=re.M,
    )


_REGISTER_RECEIVER_WITH_FLAGS_RE = re.compile(
    r'^    invoke-virtual/range \{(?P<kind>[vp])\d+ \.\. (?P=kind)(?P<hi>\d+)\}, '
    r'Landroid/content/Context;->registerReceiver\(Landroid/content/BroadcastReceiver;'
    r'Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I\)Landroid/content/Intent;\n',
    re.M,
)


def _force_receiver_not_exported(code: str):
    """Mask RECEIVER_EXPORTED (0x2) and set RECEIVER_NOT_EXPORTED (0x4) on
    every Context.registerReceiver(..., int flags) range call in code.
    Returns (code, patched, already_patched)."""
    out = []
    pos = 0
    patched = already = 0
    for match in _REGISTER_RECEIVER_WITH_FLAGS_RE.finditer(code):
        reg = f'{match.group("kind")}{match.group("hi")}'
        mask = (
            f'    and-int/lit8 {reg}, {reg}, -0x3\n'
            '\n'
            f'    or-int/lit8 {reg}, {reg}, 0x4\n'
            '\n'
        )
        out.append(code[pos:match.start()])
        if code[:match.start()].endswith(mask):
            already += 1
        else:
            out.append(mask)
            patched += 1
        out.append(match.group(0))
        pos = match.end()
    out.append(code[pos:])
    return ''.join(out), patched, already


def blob_fixup_oppogallery_receiver_flags(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Gallery's broadcast bus registers dynamic receivers with caller-provided
    # flags; force them to RECEIVER_NOT_EXPORTED. Two sites (16.0.8 names in
    # brackets): BroadcastDispatcher's ProxyReceiver registration [ey/gy] and
    # ActionReceiver.register [ActionReceiver/a10].
    if tmp_dir is None:
        return

    sites = (
        (
            'BroadcastDispatcher ProxyReceiver',
            '.source "BroadcastDispatcher.kt"',
            'Lcom/oplus/gallery/foundation/uikit/broadcast/bus/ProxyReceiver;->',
        ),
        (
            'ActionReceiver',
            '.class public final Lcom/oplus/gallery/foundation/uikit/broadcast/bus/ActionReceiver;',
            'Lcom/oplus/gallery/foundation/uikit/broadcast/bus/ActionReceiver;->',
        ),
    )
    for label, file_anchor, method_anchor in sites:
        found = False
        for smali in _grep_smali(tmp_dir, file_anchor):
            data = smali.read_text(encoding='utf-8')
            if not data.startswith('.class') or file_anchor not in data:
                continue

            def patch_method(match):
                nonlocal found
                method = match.group(0)
                if method_anchor not in method:
                    return method
                method, patched, already = _force_receiver_not_exported(method)
                if patched or already:
                    found = True
                return method

            fixed = _SMALI_METHOD_RE.sub(patch_method, data)
            if fixed != data:
                smali.write_text(fixed, encoding='utf-8')
        if not found:
            raise ValueError(f'OppoGallery2 {label} receiver flag patch point not found')


def blob_fixup_oppogallery_wallpaper_attach_intent(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    # Replace PictureEditorDM's set-as-wallpaper method (16.0.8/16.0.10:
    # a(Activity, Uri), tag "WallpaperSetUtil") which launches the OEM
    # WallpaperManager crop intent, with a generic ATTACH_DATA chooser. The
    # method is located by the getCropAndSetWallpaperIntent call, not by name.
    smali = _smali_class_file(tmp_dir, 'Lcom/oplus/gallery/pictureeditorpage/PictureEditorDM;')
    if smali is None:
        raise ValueError('OppoGallery2 PictureEditorDM class not found')
    data = smali.read_text(encoding='utf-8')
    method_re = re.compile(
        r'(?ms)^\.method (public final [\w$]+\(Landroid/app/Activity;Landroid/net/Uri;\)V)\n.*?^\.end method'
    )
    targets = [
        m for m in method_re.finditer(data)
        if 'Landroid/app/WallpaperManager;->getCropAndSetWallpaperIntent(' in m.group(0)
    ]
    if not targets:
        if any('"android.intent.action.ATTACH_DATA"' in m.group(0) for m in method_re.finditer(data)):
            return
        raise ValueError('OppoGallery2 wallpaper attach intent patch point not found')
    if len(targets) > 1:
        raise ValueError('OppoGallery2 wallpaper attach intent patch point is ambiguous')
    target = targets[0]
    replacement = (
        f'.method {target.group(1)}\n'
        '    .locals 3\n'
        '\n'
        '    const-string p0, "activity"\n'
        '\n'
        '    invoke-static {p1, p0}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V\n'
        '\n'
        '    const-string p0, "pickedItem"\n'
        '\n'
        '    invoke-static {p2, p0}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V\n'
        '\n'
        '    new-instance v0, Landroid/content/Intent;\n'
        '\n'
        '    const-string v1, "android.intent.action.ATTACH_DATA"\n'
        '\n'
        '    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V\n'
        '\n'
        '    const-string v1, "image/*"\n'
        '\n'
        '    invoke-virtual {v0, p2, v1}, Landroid/content/Intent;->setDataAndType(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;\n'
        '\n'
        '    const/4 v2, 0x1\n'
        '\n'
        '    invoke-virtual {v0, v2}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;\n'
        '\n'
        '    const-string v2, "mimeType"\n'
        '\n'
        '    invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n'
        '\n'
        '    invoke-virtual {p1, v0}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V\n'
        '\n'
        '    return-void\n'
        '.end method'
    )
    smali.write_text(data[:target.start()] + replacement + data[target.end():], encoding='utf-8')


def blob_fixup_oppogallery_safe_box_custom_flag(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Force the "feature_is_support_user_custom_safe_box" config to true by
    # short-circuiting ConfigAbilityWrapper.getBoolean(configId, default, ...)
    # [16.0.8: mn4.f, 16.0.10: u9a.c], which every u9a.b/u9a.d caller funnels into.
    if tmp_dir is None:
        return

    label = ':oplus_safe_box_config_default'
    getter = re.compile(
        r'(?ms)^(\.method public static final (?P<name>\w+)\(Ljava/lang/String;ZZ\)Z\n'
        r'    \.locals [1-9]\d*\n'
        r'(?:(?!^\.end method)(?!^    :).)*?'
        r'    const-string (?P<tmp>v\d+), "configId"\n'
        + _SMALI_GAP +
        r'    invoke-static \{p0, (?P=tmp)\}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter\(Ljava/lang/Object;Ljava/lang/String;\)V\n'
        r'\n)'
    )
    patched = already = 0
    for smali in _grep_smali(tmp_dir, '.source "ConfigAbilityWrapper.kt"'):
        data = smali.read_text(encoding='utf-8')
        if label in data:
            already += 1
            continue

        def insert(match):
            tmp = match.group('tmp')
            name = match.group('name')
            return (
                match.group(1)
                + f'    const-string {tmp}, "feature_is_support_user_custom_safe_box"\n'
                '\n'
                f'    invoke-static {{p0, {tmp}}}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z\n'
                '\n'
                f'    move-result {tmp}\n'
                '\n'
                f'    if-eqz {tmp}, {label}_{name}\n'
                '\n'
                '    const/4 p0, 0x1\n'
                '\n'
                '    return p0\n'
                '\n'
                f'    {label}_{name}\n'
                f'    const-string {tmp}, "configId"\n'
                '\n'
            )

        fixed, count = getter.subn(insert, data)
        if count:
            smali.write_text(fixed, encoding='utf-8')
            patched += count
    if patched + already != 1:
        raise ValueError(
            f'OppoGallery2 SafeBox config patch point not found '
            f'(ConfigAbilityWrapper getBoolean matches: {patched} new, {already} patched)'
        )


_GCLOUD_ENTRY_POINT = 'Lcom/oplus/gallery/business_lib/cloudsync/EntryPoint;'


def _smali_class_by_debug_metadata(tmp_dir, kotlin_name: str):
    for smali in _grep_smali(tmp_dir, f'    c = "{kotlin_name}"'):
        data = smali.read_text(encoding='utf-8')
        return smali, data, _smali_class_name(data)
    return None, None, None


def _gcloud_consent_lambda_and_scope(tmp_dir):
    """Find GCloudSyncStatusManager.gotoGrantConnectionConsent's suspend lambda
    and the application CoroutineScope singleton Gallery launches it on."""
    _, data, consent = _smali_class_by_debug_metadata(
        tmp_dir,
        'com.oplus.gallery.framework.abilities.gcloudsync.GCloudSyncStatusManager$gotoGrantConnectionConsent$1',
    )
    ctor = f'.method public constructor <init>({_GCLOUD_ENTRY_POINT}Lkotlin/coroutines/Continuation;)V'
    if consent is None or ctor not in data:
        raise ValueError('OppoGallery2 gotoGrantConnectionConsent lambda not found')
    launch = re.compile(
        r'    sget-object [vp]\d+, (?P<scope>L[^;]+;)->(?P<field>\w+):(?P=scope)\n'
        + _SMALI_GAP +
        r'    invoke-static \{\}, Lkotlinx/coroutines/Dispatchers;->getIO\(\)Lkotlinx/coroutines/CoroutineDispatcher;\n'
        + _SMALI_GAP +
        r'    move-result-object [vp]\d+\n'
        + _SMALI_GAP +
        rf'    new-instance [vp]\d+, {re.escape(consent)}\n'
    )
    for smali in _grep_smali(tmp_dir, f'{consent}-><init>('):
        match = launch.search(smali.read_text(encoding='utf-8'))
        if match:
            return consent, match.group('scope'), match.group('field')
    raise ValueError('OppoGallery2 gotoGrantConnectionConsent launch scope not found')




def blob_fixup_oppogallery_google_photos_consent_on_verify_failure(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # GCloudPageHelper.launchBackupPage registers an onAppStateChanged(Boolean)
    # listener [16.0.8: bi8$a, 16.0.10: d2h] that only launches the backup /
    # consent page coroutine when verifyAppState succeeded. Drop that guard.
    if tmp_dir is None:
        return

    _, _, page_lambda = _smali_class_by_debug_metadata(
        tmp_dir,
        'com.oplus.gallery.framework.abilities.gcloudsync.utils.GCloudPageHelper$launchBackupPage$1$1$onAppStateChanged$1',
    )
    if page_lambda is None:
        raise ValueError('OppoGallery2 GCloudPageHelper onAppStateChanged lambda not found')

    guard = re.compile(
        r'(?P<guard>    if-eqz p1, :cond_\w+\n|    nop\n)'
        r'(?P<rest>' + _SMALI_GAP +
        r'    sget-object [vp]\d+, (?P<scope>L[^;]+;)->\w+:(?P=scope)\n'
        r'(?:(?!    :|\.end method)[^\n]*\n)*?'
        rf'    new-instance [vp]\d+, {re.escape(page_lambda)}\n)'
    )
    patched = already = 0
    for smali in _grep_smali(tmp_dir, page_lambda):
        data = smali.read_text(encoding='utf-8')
        if _smali_class_name(data) == page_lambda:
            continue

        def patch_method(match):
            nonlocal patched, already
            method = match.group(0)
            if not re.match(r'\.method public (?:final )?\w+\(Z\)V\n', method):
                return method
            found = guard.search(method)
            if not found:
                return method
            if found.group('guard') == '    nop\n':
                already += 1
                return method
            patched += 1
            return method[:found.start()] + '    nop\n' + found.group('rest') + method[found.end():]

        fixed = _SMALI_METHOD_RE.sub(patch_method, data)
        if fixed != data:
            smali.write_text(fixed, encoding='utf-8')
    if patched + already != 1:
        raise ValueError(
            f'OppoGallery2 GCloudPageHelper verify-state guard not found '
            f'({patched} new, {already} patched)'
        )


def blob_fixup_oppogallery_google_photos_launch_consent_after_verify_failure(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # When GCloudSyncStatusManager.verifyAppState fails, still request the
    # Google Photos connection consent (gotoGrantConnectionConsent(SETTINGS)),
    # launched on Gallery's app scope with Dispatchers.IO like the stock caller.
    if tmp_dir is None:
        return

    smali, data, _ = _smali_class_by_debug_metadata(
        tmp_dir,
        'com.oplus.gallery.framework.abilities.gcloudsync.GCloudSyncStatusManager$verifyAppState$1',
    )
    if smali is None:
        raise ValueError('OppoGallery2 GCloudSyncStatusManager verifyAppState lambda not found')
    consent, scope, scope_field = _gcloud_consent_lambda_and_scope(tmp_dir)
    if f'{consent}-><init>(' in data:
        return

    failure = re.compile(
        r'(    const-string(?:/jumbo)? [vp]\d+, "verifyAppState failure\. e:"\n'
        r'(?:(?!    :|\.end method)[^\n]*\n)*?'
        r'    invoke-static \{[^}]*\}, L[^;]+;->\w+\(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;\)V\n'
        + _SMALI_GAP + r')'
        r'(    :cond_\w+\n)'
    )

    def patch_method(match):
        method = match.group(0)
        if not method.startswith('.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;\n'):
            return method
        locals_count = int(re.search(r'^    \.locals (\d+)$', method, re.M).group(1))
        if locals_count + 7 > 16:
            raise ValueError('OppoGallery2 verifyAppState has too many registers for consent launch')
        r = [f'v{locals_count + i}' for i in range(7)]
        insert = (
            f'    sget-object {r[1]}, {scope}->{scope_field}:{scope}\n'
            '\n'
            '    invoke-static {}, Lkotlinx/coroutines/Dispatchers;->getIO()Lkotlinx/coroutines/CoroutineDispatcher;\n'
            '\n'
            f'    move-result-object {r[2]}\n'
            '\n'
            f'    const/4 {r[3]}, 0x0\n'
            '\n'
            f'    new-instance {r[4]}, {consent}\n'
            '\n'
            f'    sget-object {r[0]}, {_GCLOUD_ENTRY_POINT}->SETTINGS:{_GCLOUD_ENTRY_POINT}\n'
            '\n'
            f'    invoke-direct {{{r[4]}, {r[0]}, {r[3]}}}, {consent}-><init>({_GCLOUD_ENTRY_POINT}Lkotlin/coroutines/Continuation;)V\n'
            '\n'
            f'    const/4 {r[5]}, 0x2\n'
            '\n'
            f'    const/4 {r[6]}, 0x0\n'
            '\n'
            f'    invoke-static/range {{{r[1]} .. {r[6]}}}, Lkotlinx/coroutines/BuildersKt;->launch$default(Lkotlinx/coroutines/CoroutineScope;Lkotlin/coroutines/CoroutineContext;Lkotlinx/coroutines/CoroutineStart;Lkotlin/jvm/functions/Function2;ILjava/lang/Object;)Lkotlinx/coroutines/Job;\n'
            '\n'
        )
        method, count = failure.subn(lambda m: m.group(1) + insert + m.group(2), method, count=1)
        if count:
            method = _smali_set_min_locals(method, locals_count + 7)
        return method

    fixed = _SMALI_METHOD_RE.sub(patch_method, data)
    if fixed == data:
        raise ValueError('OppoGallery2 verifyAppState failure patch point not found')
    smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_hide_google_photos_backup_settings(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    # 1. Photo page overflow: drop action_backup_to_cloud from the menu
    #    definition map built in PhotoMenuDefinition.kt [16.0.8: g0i].
    backup_id = 'Lcom/oplus/gallery/photo_page/R$id;->action_backup_to_cloud:I'
    menu_entry = re.compile(
        rf'    sget (?P<id>v\d+), {re.escape(backup_id)}\n'
        r'(?:(?!    :|\.end method)[^\n]*\n)*?'
        r'    const-string (?:v\d+), "action_backup_to_cloud"\n'
        + _SMALI_GAP +
        r'    invoke-static/range \{(?P<map>v\d+) \.\. v\d+\}, L[^;]+;->\w+\(Ljava/util/LinkedHashMap;ILjava/lang/String;JZZ\)V\n'
        r'(?P<tail>' + _SMALI_GAP + r'    sget (?P=id), )'
    )
    menu_found = False
    for smali in _grep_smali(tmp_dir, '.source "PhotoMenuDefinition.kt"'):
        data = smali.read_text(encoding='utf-8')
        if backup_id not in data:
            continue
        if 'Ljava/util/LinkedHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;' in data:
            menu_found = True
            continue

        def remove_entry(match):
            reg, map_reg = match.group('id'), match.group('map')
            head = match.group(0)[:match.start('tail') - match.start()]
            return (
                head
                + '\n'
                f'    sget {reg}, {backup_id}\n'
                '\n'
                f'    invoke-static {{{reg}}}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;\n'
                '\n'
                f'    move-result-object {reg}\n'
                '\n'
                f'    invoke-virtual {{{map_reg}, {reg}}}, Ljava/util/LinkedHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;\n'
                + match.group('tail')
            )

        fixed, count = menu_entry.subn(remove_entry, data, count=1)
        if count:
            smali.write_text(fixed, encoding='utf-8')
            menu_found = True
    if not menu_found:
        raise ValueError('OppoGallery2 photo menu action_backup_to_cloud patch point not found')

    # 2. PhotoMenuBackupToCloudActionRule [16.0.8: urh, 16.0.10: vzv]: override
    #    the PhotoMenuActionRule base's only open no-arg boolean hook
    #    [16.0.8/16.0.10: m()Z] to return false, as the 16.0.8 patch did.
    rule_found = False
    for smali in _grep_smali(tmp_dir, '.source "PhotoMenuBackupToCloudActionRule.kt"'):
        data = smali.read_text(encoding='utf-8')
        if not data.startswith('.class'):
            continue
        super_cls = re.search(r'^\.super (L[^;]+;)$', data, re.M).group(1)
        super_file = _smali_class_file(tmp_dir, super_cls)
        super_data = super_file.read_text(encoding='utf-8') if super_file else ''
        if '.source "PhotoMenuActionRule.kt"' not in super_data:
            continue
        hooks = re.findall(r'^\.method public (\w+)\(\)Z$', super_data, re.M)
        if len(hooks) != 1:
            raise ValueError(f'OppoGallery2 PhotoMenuActionRule boolean hook is ambiguous: {hooks}')
        rule_found = True
        if re.search(rf'^\.method public (?:final )?{hooks[0]}\(\)Z$', data, re.M):
            continue
        data = data.rstrip('\n') + (
            '\n'
            '\n'
            f'.method public final {hooks[0]}()Z\n'
            '    .locals 1\n'
            '\n'
            '    const/4 v0, 0x0\n'
            '\n'
            '    return v0\n'
            '.end method\n'
        )
        smali.write_text(data, encoding='utf-8')
    if not rule_found:
        raise ValueError('OppoGallery2 PhotoMenuBackupToCloudActionRule not found')

    # 3. Settings: remove the Google Photos cloud sync preferences right after
    #    onCreatePreferences() inflates the screen.
    done = ':oplus_hide_google_photos_backup_settings_done'
    marker = re.compile(
        r'(?m)^(?P<labels>(?:    :\w+\n)*)'
        r'(?P<load>    iget-object (?P<screen>[vp]\d+), (?P<this>[vp]\d+), '
        r'Lcom/oplus/gallery/settingpage/SettingsActivity\$SettingFragment;->\w+:Landroidx/preference/PreferenceScreen;\n)'
        r'(?P<gap>' + _SMALI_GAP + r')'
        r'    const-string (?P<tmp>[vp]\d+), "pref_category_key_sending"\n'
    )
    settings_found = False
    for smali in sorted(Path(tmp_dir).glob('smali*/com/oplus/gallery/settingpage/SettingsActivity$SettingFragment.smali')):
        data = smali.read_text(encoding='utf-8')
        if done in data:
            settings_found = True
            continue
        match = marker.search(data)
        if not match:
            continue
        screen, tmp = match.group('screen'), match.group('tmp')
        insert = match.group('load') + '\n' + f'    if-eqz {screen}, {done}\n' + '\n'
        for key in (
            'pref_category_key_cloud_sync',
            'pref_category_cloud_sync_key',
            'pref_key_auto_sync_2',
            'pref_category_key_cloud_storage_space',
        ):
            insert += (
                f'    const-string {tmp}, "{key}"\n'
                '\n'
                f'    invoke-virtual {{{screen}, {tmp}}}, Landroidx/preference/PreferenceGroup;->removePreferenceRecursively(Ljava/lang/CharSequence;)Z\n'
                '\n'
            )
        insert += f'    {done}\n'
        fixed = data[:match.start('load')] + insert + data[match.start('load'):]
        smali.write_text(fixed, encoding='utf-8')
        settings_found = True
    if not settings_found:
        raise ValueError('OppoGallery2 SettingsActivity cloud sync preference patch point not found')


def blob_fixup_stdid_receiver_flags(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali/com/oplus/stdid/AppApplication.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    old = (
        '.method public final onCreate()V\n'
        '    .locals 5\n'
    )
    new = (
        '.method public final onCreate()V\n'
        '    .locals 10\n'
    )
    fixed = data.replace(old, new, 1)
    old = (
        '    invoke-virtual {p0, v4, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;\n'
    )
    new = (
        '    move-object v5, v4\n'
        '\n'
        '    move-object v4, p0\n'
        '\n'
        '    move-object v6, v0\n'
        '\n'
        '    move-object v7, v1\n'
        '\n'
        '    move-object v8, v1\n'
        '\n'
        '    const/4 v9, 0x4\n'
        '\n'
        '    invoke-virtual/range {v4 .. v9}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;\n'
    )
    fixed = fixed.replace(old, new, 1)
    old = (
        '    invoke-virtual {p0, v4, v0, v2, v1}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;\n'
    )
    new = (
        '    move-object v5, v4\n'
        '\n'
        '    move-object v4, p0\n'
        '\n'
        '    move-object v6, v0\n'
        '\n'
        '    move-object v7, v2\n'
        '\n'
        '    move-object v8, v1\n'
        '\n'
        '    const/4 v9, 0x4\n'
        '\n'
        '    invoke-virtual/range {v4 .. v9}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;\n'
    )
    fixed = fixed.replace(old, new, 1)
    # Both rewritten calls reuse v1 as the null permission/Handler argument.
    if '.method public final onCreate()V\n    .locals 10\n' not in fixed or (
            '    const/4 v1, 0x0\n' not in fixed) or (
            fixed.count('Landroid/os/Handler;I)Landroid/content/Intent;') != 2) or (
            'registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)' in fixed) or (
            'Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;' in fixed):
        raise ValueError('StdID AppApplication registerReceiver patch points not found')
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_system_share_helper(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Use Gallery's existing system-share branch instead of the OnePlus custom
    # share page. This preserves Gallery's own media path -> content URI/MIME
    # conversion before Android's platform chooser is opened.
    if tmp_dir is None:
        return

    helper = None
    for smali in _grep_smali(tmp_dir, '"feature_is_support_user_custom_gallery_share"'):
        data = smali.read_text(encoding='utf-8')
        if '.source "ShareHelper.kt"' in data and '"external_primary"' in data:
            helper = smali
            break
    if helper is None:
        raise ValueError('OppoGallery2 ShareHelper smali not found')
    data = helper.read_text(encoding='utf-8')

    # 1. Skip the custom-share-page Lazy<Boolean> check and always take the
    #    system chooser branch.
    share_marker = '    # oplus_system_share_helper\n'
    custom_check = re.compile(
        r'    sget-object (?P<r>v\d+), L[^;]+;->\w+:Lkotlin/Lazy;\n'
        + _SMALI_GAP +
        r'    invoke-interface \{(?P=r)\}, Lkotlin/Lazy;->getValue\(\)Ljava/lang/Object;\n'
        + _SMALI_GAP +
        r'    move-result-object (?P=r)\n'
        + _SMALI_GAP +
        r'    check-cast (?P=r), Ljava/lang/Boolean;\n'
        + _SMALI_GAP +
        r'    invoke-virtual \{(?P=r)\}, Ljava/lang/Boolean;->booleanValue\(\)Z\n'
        + _SMALI_GAP +
        r'    move-result (?P=r)\n'
        + _SMALI_GAP +
        r'    const/4 (?P<zero>v\d+), 0x0\n'
        + _SMALI_GAP +
        r'    if-nez (?P=r), (?P<system>:cond_\w+)\n'
    )
    share_state = {'patched': 0, 'already': 0}

    def patch_share(match):
        method = match.group(0)
        if '"feature_is_support_user_custom_gallery_share"' not in method:
            return method
        if share_marker in method:
            share_state['already'] += 1
            return method
        method, count = custom_check.subn(
            lambda m: (
                share_marker
                + f'    const/4 {m.group("zero")}, 0x0\n'
                '\n'
                f'    goto {m.group("system")}\n'
            ),
            method,
            count=1,
        )
        share_state['patched'] += count
        return method

    fixed = _SMALI_METHOD_RE.sub(patch_share, data)
    if share_state['patched'] + share_state['already'] != 1:
        raise ValueError('OppoGallery2 ShareHelper system-share patch point not found')

    # 2. Prefer a GalleryFileProvider content:// URI built from the item's
    #    file path; keep the stock MediaStore URI logic as fallback.
    uri_label = ':oplus_share_uri_fallback'
    uri_method = re.compile(
        r'(?ms)^\.method public static (?:final )?\w+\((?P<path>L[^;]+;)\)Landroid/net/Uri;\n'
        r'.*?^\.end method\n'
    )
    uri_match = next(
        (m for m in uri_method.finditer(fixed) if '"external_primary"' in m.group(0)),
        None,
    )
    if uri_match is None:
        raise ValueError('OppoGallery2 ShareHelper URI patch point not found')
    if uri_label not in uri_match.group(0):
        path_cls = uri_match.group('path')
        path_file = _smali_class_file(tmp_dir, path_cls)
        path_data = path_file.read_text(encoding='utf-8') if path_file else ''
        media_object = 'Lcom/oplus/gallery/business_lib/model/data/base/MediaObject;'
        getters = re.findall(rf'^\.method public final (\w+)\(\){re.escape(media_object)}$', path_data, re.M)
        if len(getters) != 1:
            raise ValueError(f'OppoGallery2 Path MediaObject getter not found: {getters}')

        media_item = None
        for smali in _grep_smali(tmp_dir, '.source "MediaItem.java"'):
            item_data = smali.read_text(encoding='utf-8')
            if f'.super {media_object}' in item_data:
                media_item = _smali_class_name(item_data)
                break
        if media_item is None:
            raise ValueError('OppoGallery2 MediaItem class not found')
        file_path_getter = re.compile(
            rf'invoke-virtual \{{([vp]\d+)\}}, {re.escape(media_item)}->(\w+)\(\)Ljava/lang/String;\n'
            + _SMALI_GAP + r'    move-result-object \1\n'
            + _SMALI_GAP + r'    const-string(?:/jumbo)? [vp]\d+, "getFilePath\(\.\.\.\)"'
        )
        names = set()
        for smali in _grep_smali(tmp_dir, '"getFilePath(...)"'):
            names.update(m.group(2) for m in file_path_getter.finditer(smali.read_text(encoding='utf-8')))
        if len(names) != 1:
            raise ValueError(f'OppoGallery2 MediaItem.getFilePath not found: {sorted(names)}')
        file_path_name = names.pop()

        app_context = None
        for smali in _grep_smali(tmp_dir, '.source "ContextGetter.kt"'):
            ctx_data = smali.read_text(encoding='utf-8')
            field = re.search(
                r'^\.field public static (\w+):(Landroid/content/Context;|Lcom/coloros/gallery3d/app/App;)$',
                ctx_data,
                re.M,
            )
            if field:
                app_context = f'{_smali_class_name(ctx_data)}->{field.group(1)}:{field.group(2)}'
                break
        if app_context is None:
            raise ValueError('OppoGallery2 ContextGetter application context not found')

        provider = 'Lcom/oplus/gallery/foundation/fileaccess/GalleryFileProvider$a;'
        provider_file = _smali_class_file(tmp_dir, provider)
        provider_data = provider_file.read_text(encoding='utf-8') if provider_file else ''
        provider_method = re.search(
            r'^\.method public static varargs (\w+)\(Landroid/content/Context;(L[^;]+;)\[Ljava/lang/String;\)Landroid/net/Uri;$',
            provider_data,
            re.M,
        )
        if provider_method is None:
            raise ValueError('OppoGallery2 GalleryFileProvider getUriForFile not found')
        file_cls = provider_method.group(2)
        file_cls_file = _smali_class_file(tmp_dir, file_cls)
        if file_cls_file is None or '.method public constructor <init>(Ljava/lang/String;)V' not in file_cls_file.read_text(encoding='utf-8'):
            raise ValueError('OppoGallery2 GalleryFileProvider File(String) constructor not found')

        prefix = (
            f'    invoke-virtual {{p0}}, {path_cls}->{getters[0]}(){media_object}\n'
            '\n'
            '    move-result-object v0\n'
            '\n'
            f'    instance-of v1, v0, {media_item}\n'
            '\n'
            f'    if-eqz v1, {uri_label}\n'
            '\n'
            f'    check-cast v0, {media_item}\n'
            '\n'
            f'    invoke-virtual {{v0}}, {media_item}->{file_path_name}()Ljava/lang/String;\n'
            '\n'
            '    move-result-object v0\n'
            '\n'
            f'    if-eqz v0, {uri_label}\n'
            '\n'
            '    invoke-virtual {v0}, Ljava/lang/String;->length()I\n'
            '\n'
            '    move-result v1\n'
            '\n'
            f'    if-lez v1, {uri_label}\n'
            '\n'
            f'    sget-object v1, {app_context}\n'
            '\n'
            f'    if-eqz v1, {uri_label}\n'
            '\n'
            f'    new-instance v2, {file_cls}\n'
            '\n'
            f'    invoke-direct {{v2, v0}}, {file_cls}-><init>(Ljava/lang/String;)V\n'
            '\n'
            '    const/4 v0, 0x0\n'
            '\n'
            '    new-array v0, v0, [Ljava/lang/String;\n'
            '\n'
            f'    invoke-static {{v1, v2, v0}}, {provider}->{provider_method.group(1)}(Landroid/content/Context;{file_cls}[Ljava/lang/String;)Landroid/net/Uri;\n'
            '\n'
            '    move-result-object v0\n'
            '\n'
            f'    if-eqz v0, {uri_label}\n'
            '\n'
            '    return-object v0\n'
            '\n'
            f'    {uri_label}\n'
        )
        method = uri_match.group(0)
        method, count = re.subn(
            r'(    invoke-static \{p0, v\d+\}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter\(Ljava/lang/Object;Ljava/lang/String;\)V\n\n)',
            lambda m: m.group(1) + prefix,
            method,
            count=1,
        )
        if count != 1:
            raise ValueError('OppoGallery2 ShareHelper URI patch point not found')
        method = _smali_set_min_locals(method, 3)
        fixed = fixed[:uri_match.start()] + method + fixed[uri_match.end():]

    if fixed != data:
        helper.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_op15_native_libs(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    data = manifest.read_text(encoding='utf-8') if manifest.exists() else ''
    old = [
        '        <uses-native-library android:name="/odm/lib64/aiboost/libaiboost.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/libaiboost_qnn_external_delegate.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/libQnnHtp.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/libQnnHtpPrepare.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/libQnnHtpV75Stub.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/libQnnSystem.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/libtransformer_lite.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/Skel_signed/aiboost/libQnnHtpV75Skel.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/aiboost/Skel_unsigned/libQnnHtpV75Skel.so" android:required="false"/>\n',
    ]
    new = [
        '        <uses-native-library android:name="/odm/lib64/libQnnHtp.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/libQnnHtpPrepare.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/libQnnHtpV81Stub.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/libQnnHtpV81CalculatorStub.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/libQnnSaver.so" android:required="false"/>\n',
        '        <uses-native-library android:name="/odm/lib64/libQnnSystem.so" android:required="false"/>\n',
    ]

    fixed = data
    # 16.0.10 declares libaiboost.so twice; drop every stale aiboost entry and
    # put the OP15 QNN libs where the first one was.
    first = min((fixed.find(line) for line in old if line in fixed), default=-1)
    if first >= 0:
        rest = fixed[first:]
        for line in old:
            rest = rest.replace(line, '')
        fixed = fixed[:first] + ''.join(new) + rest
    elif new[-1] not in fixed:
        insert_after = '        <uses-native-library android:name="libOpenCL.so" android:required="true"/>\n'
        if insert_after not in fixed:
            raise ValueError('OppoGallery2 native library patch point not found')
        fixed = fixed.replace(insert_after, insert_after + ''.join(new), 1)

    if fixed != data:
        manifest.write_text(fixed, encoding='utf-8')

    lib_dir = Path(tmp_dir) / 'lib/arm64-v8a'
    lib_dir.mkdir(parents=True, exist_ok=True)
    source_dir = Path(__file__).resolve().parent / 'configs/lib64'
    for lib in (
        'libQnnHtp.so',
        'libQnnHtpPrepare.so',
        'libQnnHtpV81Stub.so',
        'libQnnHtpV81CalculatorStub.so',
        'libQnnSaver.so',
        'libQnnSystem.so',
    ):
        shutil.copy2(source_dir / lib, lib_dir / lib)


def blob_fixup_oppogallery_popup_enter(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/COUIPopupMenuRootView.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    old = (
        '    iget-object p0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mController:Lcom/coui/appcompat/poplist/BasePopupMenuAnimationController;\n'
        '\n'
        '    .line 22\n'
        '    .line 23\n'
        '    invoke-virtual {p0}, Lcom/coui/appcompat/poplist/BasePopupMenuAnimationController;->startMainMenuEnter()V\n'
    )
    new = (
        '    iget-object p0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mController:Lcom/coui/appcompat/poplist/BasePopupMenuAnimationController;\n'
        '\n'
        '    .line 22\n'
        '    .line 23\n'
        '    const/4 v1, 0x0\n'
        '\n'
        '    invoke-virtual {p0, v1}, Lcom/coui/appcompat/poplist/BasePopupMenuAnimationController;->startMainMenuEnter(Z)V\n'
    )
    fixed = data.replace(old, new, 1)
    old = (
        '    .line 6\n'
        '    :cond_0\n'
        '    invoke-virtual {v0}, Lcom/coui/appcompat/poplist/BasePopupMenuAnimationController;->startMainMenuEnter()V\n'
    )
    new = (
        '    .line 6\n'
        '    :cond_0\n'
        '    const/4 p0, 0x0\n'
        '\n'
        '    invoke-virtual {v0, p0}, Lcom/coui/appcompat/poplist/BasePopupMenuAnimationController;->startMainMenuEnter(Z)V\n'
    )
    fixed = fixed.replace(old, new, 1)
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_popup_width(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/COUIPopupListWindow.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    old = (
        '    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I\n'
        '\n'
        '    .line 47\n'
        '    .line 48\n'
        '    .line 49\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mMainMenuAdapter:Lcom/coui/appcompat/poplist/DefaultAdapter;\n'
    )
    new = (
        '    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I\n'
        '\n'
        '    move p0, v2\n'
        '\n'
        '    return p0\n'
        '\n'
        '    .line 47\n'
        '    .line 48\n'
        '    .line 49\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mMainMenuAdapter:Lcom/coui/appcompat/poplist/DefaultAdapter;\n'
    )
    fixed = data.replace(old, new)
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_popup_visibility(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/COUIPopupListWindow.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = data.replace(
        '    iget-object p2, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mContentView:Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;\n'
        '\n'
        '    invoke-virtual {p2}, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->showMainMenu()V\n'
        '\n'
        '    goto :goto_4\n',
        '    iget-object p2, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mContentView:Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;\n'
        '\n'
        '    invoke-virtual {p2}, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->showMainMenu()V\n'
        '\n'
        '    invoke-virtual {p0, v2}, Landroid/widget/PopupWindow;->setTouchable(Z)V\n'
        '\n'
        '    invoke-virtual {p0, v2}, Landroid/widget/PopupWindow;->setFocusable(Z)V\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/widget/PopupWindow;->update()V\n'
        '\n'
        '    goto :goto_4\n',
    )
    fixed = fixed.replace(
        '    invoke-super {p0, p2, v3, v3, v3}, Landroid/widget/PopupWindow;->showAtLocation(Landroid/view/View;III)V\n',
        '    invoke-super {p0, p2, v3, v3, v3}, Landroid/widget/PopupWindow;->showAtLocation(Landroid/view/View;III)V\n'
        '\n'
        '    invoke-virtual {p0, v2}, Landroid/widget/PopupWindow;->setTouchable(Z)V\n'
        '\n'
        '    invoke-virtual {p0, v2}, Landroid/widget/PopupWindow;->setFocusable(Z)V\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/widget/PopupWindow;->update()V\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_theme_fallbacks(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes7/com/oplus/aiunit/vision/ho4.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = _replace_smali_method(
        data,
        'public static final a(Landroid/content/res/Configuration;)I',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, -0x1\n'
        '\n'
        '    return v0\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public static final b(Landroid/content/res/Configuration;)I',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, -0x1\n'
        '\n'
        '    return v0\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/view/ViewNative.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = _replace_smali_method(
        data,
        'public static setScrollX(Landroid/view/View;I)V',
        '    .locals 0\n'
        '\n'
        '    invoke-virtual {p0, p1}, Landroid/view/View;->setScrollX(I)V\n'
        '\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public static setScrollY(Landroid/view/View;I)V',
        '    .locals 0\n'
        '\n'
        '    invoke-virtual {p0, p1}, Landroid/view/View;->setScrollY(I)V\n'
        '\n'
        '    return-void\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/theme/COUIThemeOverlay.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = _replace_smali_method(
        data,
        'private canReachBaseConfiguration()Z',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, 0x0\n'
        '\n'
        '    return v0\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'private getExtraConfig(Landroid/content/res/Configuration;)Loplus/content/res/OplusExtraConfiguration;',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, 0x0\n'
        '\n'
        '    return-object v0\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oppogallery_popup_text_colors(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/preference/COUIPreferenceUtils.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = _replace_smali_method(
        data,
        'public static bindAssignmentView(Landroidx/preference/PreferenceViewHolder;Ljava/lang/CharSequence;I)V',
        '    .locals 2\n'
        '\n'
        '    sget v0, Lcom/support/preference/R$id;->assignment:I\n'
        '\n'
        '    invoke-virtual {p0, v0}, Landroidx/preference/PreferenceViewHolder;->findViewById(I)Landroid/view/View;\n'
        '\n'
        '    move-result-object p0\n'
        '\n'
        '    check-cast p0, Landroid/widget/TextView;\n'
        '\n'
        '    if-eqz p0, :cond_2\n'
        '\n'
        '    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z\n'
        '\n'
        '    move-result v0\n'
        '\n'
        '    if-nez v0, :cond_1\n'
        '\n'
        '    invoke-virtual {p0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V\n'
        '\n'
        '    const/4 p1, 0x0\n'
        '\n'
        '    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V\n'
        '\n'
        '    const v1, -0x99999a\n'
        '\n'
        '    invoke-virtual {p0, v1}, Landroid/widget/TextView;->setTextColor(I)V\n'
        '\n'
        '    goto :goto_0\n'
        '\n'
        '    :cond_1\n'
        '    const/16 p1, 0x8\n'
        '\n'
        '    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V\n'
        '\n'
        '    :cond_2\n'
        '    :goto_0\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public static setSummaryViewColor(Landroidx/preference/PreferenceViewHolder;Landroid/content/res/ColorStateList;)V',
        '    .locals 2\n'
        '\n'
        '    const v0, 0x1020010\n'
        '\n'
        '    invoke-virtual {p0, v0}, Landroidx/preference/PreferenceViewHolder;->findViewById(I)Landroid/view/View;\n'
        '\n'
        '    move-result-object p0\n'
        '\n'
        '    check-cast p0, Landroid/widget/TextView;\n'
        '\n'
        '    if-eqz p0, :cond_1\n'
        '\n'
        '    const v1, -0x99999a\n'
        '\n'
        '    invoke-virtual {p0, v1}, Landroid/widget/TextView;->setTextColor(I)V\n'
        '\n'
        '    :cond_1\n'
        '    :goto_0\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public static setTitleViewColor(Landroid/content/Context;Landroidx/preference/PreferenceViewHolder;Landroid/content/res/ColorStateList;)V',
        '    .locals 2\n'
        '\n'
        '    const p0, 0x1020016\n'
        '\n'
        '    invoke-virtual {p1, p0}, Landroidx/preference/PreferenceViewHolder;->findViewById(I)Landroid/view/View;\n'
        '\n'
        '    move-result-object p0\n'
        '\n'
        '    if-eqz p0, :cond_1\n'
        '\n'
        '    check-cast p0, Landroid/widget/TextView;\n'
        '\n'
        '    const/high16 v0, -0x1000000\n'
        '\n'
        '    invoke-virtual {p0, v0}, Landroid/widget/TextView;->setTextColor(I)V\n'
        '\n'
        '    :cond_1\n'
        '    :goto_0\n'
        '    return-void\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/textview/COUITextView.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    if data and 'protected onDraw(Landroid/graphics/Canvas;)V' not in data:
        fixed = data.replace(
            '# virtual methods\n',
            '# virtual methods\n'
            '.method protected onDraw(Landroid/graphics/Canvas;)V\n'
            '    .locals 2\n'
            '\n'
            '    const/high16 v0, -0x1000000\n'
            '\n'
            '    invoke-virtual {p0}, Landroid/widget/TextView;->getCurrentTextColor()I\n'
            '\n'
            '    move-result v1\n'
            '\n'
            '    if-eq v1, v0, :cond_0\n'
            '\n'
            '    invoke-virtual {p0, v0}, Landroid/widget/TextView;->setTextColor(I)V\n'
            '\n'
            '    :cond_0\n'
            '    invoke-super {p0, p1}, Landroidx/appcompat/widget/AppCompatTextView;->onDraw(Landroid/graphics/Canvas;)V\n'
            '\n'
            '    return-void\n'
            '.end method\n'
            '\n',
            1,
        )
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/oplus/gallery/basebiz/widget/EditorMenuItemView.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = _replace_smali_method(
        data,
        'public final setIconDrawableTintColor(I)V',
        '    .locals 1\n'
        '\n'
        '    const/high16 p1, -0x1000000\n'
        '\n'
        '    iget-object v0, p0, Lcom/oplus/gallery/basebiz/widget/EditorMenuItemView;->a:Landroid/graphics/drawable/Drawable;\n'
        '\n'
        '    if-eqz v0, :cond_0\n'
        '\n'
        '    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTint(I)V\n'
        '\n'
        '    :cond_0\n'
        '    invoke-virtual {p0}, Landroid/view/View;->postInvalidate()V\n'
        '\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public final setPaintColorFilter(I)V',
        '    .locals 2\n'
        '\n'
        '    const/high16 p1, -0x1000000\n'
        '\n'
        '    new-instance v0, Landroid/graphics/PorterDuffColorFilter;\n'
        '\n'
        '    sget-object v1, Landroid/graphics/PorterDuff$Mode;->SRC_ATOP:Landroid/graphics/PorterDuff$Mode;\n'
        '\n'
        '    invoke-direct {v0, p1, v1}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V\n'
        '\n'
        '    iget-object p1, p0, Lcom/oplus/gallery/basebiz/widget/EditorMenuItemView;->b:Landroid/graphics/Paint;\n'
        '\n'
        '    invoke-virtual {p1, v0}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/view/View;->postInvalidate()V\n'
        '\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public final setTextColor(I)V',
        '    .locals 1\n'
        '\n'
        '    const/high16 p1, -0x1000000\n'
        '\n'
        '    iget-object v0, p0, Lcom/oplus/gallery/basebiz/widget/EditorMenuItemView;->e:Landroid/graphics/Paint;\n'
        '\n'
        '    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setColor(I)V\n'
        '\n'
        '    invoke-virtual {p0}, Landroid/view/View;->postInvalidate()V\n'
        '\n'
        '    return-void\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/DefaultAdapter.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = data.replace(
        '    invoke-direct {p0, p2, p3}, Lcom/coui/appcompat/poplist/DefaultAdapter;->getTintColorByState(Landroid/content/res/ColorStateList;Lcom/coui/appcompat/poplist/PopupListItem;)I\n'
        '\n'
        '    .line 5\n'
        '    .line 6\n'
        '    .line 7\n'
        '    move-result p0\n'
        '\n'
        '    .line 8\n'
        '    invoke-virtual {p1, p0}, Landroid/widget/TextView;->setTextColor(I)V\n',
        '    const/high16 p0, -0x1000000\n'
        '\n'
        '    .line 8\n'
        '    invoke-virtual {p1, p0}, Landroid/widget/TextView;->setTextColor(I)V\n',
    )
    fixed = fixed.replace(
        '    :cond_6\n'
        '    :goto_3\n'
        '    invoke-virtual {p2}, Lcom/coui/appcompat/poplist/PopupListItem;->isChecked()Z\n',
        '    :cond_6\n'
        '    :goto_3\n'
        '    const/high16 p0, -0x1000000\n'
        '\n'
        '    invoke-virtual {p1, p0}, Landroid/widget/TextView;->setTextColor(I)V\n'
        '\n'
        '    invoke-virtual {p2}, Lcom/coui/appcompat/poplist/PopupListItem;->isChecked()Z\n',
    )
    fixed = fixed.replace(
        '    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V\n'
        '\n',
        '    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V\n'
        '\n'
        '    const/high16 v1, -0x1000000\n'
        '\n'
        '    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setTextColor(I)V\n',
        1,
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/COUIPopupListWindow.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = data.replace(
        '    :cond_1\n'
        '    invoke-virtual {v1}, Landroid/content/res/TypedArray;->recycle()V\n',
        '    :cond_1\n'
        '    iget-object v2, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mMainMenuWrapper:Lcom/coui/appcompat/poplist/RoundFrameLayout;\n'
        '\n'
        '    const/4 v3, -0x1\n'
        '\n'
        '    invoke-virtual {v2, v3}, Landroid/view/View;->setBackgroundColor(I)V\n'
        '\n'
        '    iget-object v2, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mSubMenuWrapper:Lcom/coui/appcompat/poplist/RoundFrameLayout;\n'
        '\n'
        '    invoke-virtual {v2, v3}, Landroid/view/View;->setBackgroundColor(I)V\n'
        '\n'
        '    iget-object v2, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mMainListView:Landroid/widget/ListView;\n'
        '\n'
        '    invoke-virtual {v2, v3}, Landroid/view/View;->setBackgroundColor(I)V\n'
        '\n'
        '    iget-object v2, p0, Lcom/coui/appcompat/poplist/COUIPopupListWindow;->mSubListView:Landroid/widget/ListView;\n'
        '\n'
        '    invoke-virtual {v2, v3}, Landroid/view/View;->setBackgroundColor(I)V\n'
        '\n'
        '    invoke-virtual {v1}, Landroid/content/res/TypedArray;->recycle()V\n',
        1,
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/RoundFrameLayout.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = _replace_smali_method(
        data,
        'public initUseBackgroundBlur(ZLcom/coui/appcompat/uiutil/AnimLevel;)V',
        '    .locals 2\n'
        '\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/RoundFrameLayout;->mBackgroundBlurBuilder:Lcom/coui/appcompat/uiutil/COUIBackgroundBlurBuilder;\n'
        '\n'
        '    const/4 v1, 0x0\n'
        '\n'
        '    invoke-virtual {v0, v1, p2}, Lcom/coui/appcompat/uiutil/COUIBackgroundBlurBuilder;->setUseBackgroundBlur(ZLcom/coui/appcompat/uiutil/AnimLevel;)Lcom/coui/appcompat/uiutil/COUIBackgroundBlurBuilder;\n'
        '\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public getUseBackgroundBlur()Z',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, 0x0\n'
        '\n'
        '    return v0\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public dispatchDraw(Landroid/graphics/Canvas;)V',
        '    .locals 0\n'
        '\n'
        '    invoke-super {p0, p1}, Landroid/widget/FrameLayout;->dispatchDraw(Landroid/graphics/Canvas;)V\n'
        '\n'
        '    return-void\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    smali = Path(tmp_dir) / 'smali_classes5/com/coui/appcompat/poplist/COUIPopupMenuRootView.smali'
    data = smali.read_text(encoding='utf-8') if smali.exists() else ''
    fixed = data.replace(
        '    .line 18\n'
        '    sget-boolean p3, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->DEBUG_DRAW:Z\n'
        '\n'
        '    if-eqz p3, :cond_0\n'
        '\n'
        '    .line 19\n'
        '    invoke-virtual {p0, p1}, Landroid/view/View;->setWillNotDraw(Z)V\n'
        '\n'
        '    .line 20\n'
        '    :cond_0\n',
        '    .line 18\n'
        '    invoke-virtual {p0, p1}, Landroid/view/View;->setWillNotDraw(Z)V\n'
        '\n'
        '    .line 20\n',
        1,
    )
    fixed = _replace_smali_method(
        fixed,
        'public onDraw(Landroid/graphics/Canvas;)V',
        '    .locals 0\n'
        '\n'
        '    invoke-super {p0, p1}, Landroid/view/View;->onDraw(Landroid/graphics/Canvas;)V\n'
        '\n'
        '    return-void\n',
    )
    if 'dispatchDraw(Landroid/graphics/Canvas;)V' not in fixed:
        fixed = fixed.replace(
            '\n.method public onLayout(ZIIII)V',
            '\n.method protected dispatchDraw(Landroid/graphics/Canvas;)V\n'
            '    .locals 0\n'
            '\n'
            '    return-void\n'
            '.end method\n'
            '\n'
            '.method public onLayout(ZIIII)V',
            1,
        )
    fixed = _replace_smali_method(
        fixed,
        'public onLayout(ZIIII)V',
        '    .locals 6\n'
        '\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v0, :cond_1\n'
        '\n'
        '    iget-object v1, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mDomain:Lcom/coui/appcompat/poplist/PopupMenuDomain;\n'
        '\n'
        '    if-eqz v1, :cond_0\n'
        '\n'
        '    iget-object v1, v1, Lcom/coui/appcompat/poplist/PopupMenuDomain;->mMainMenu:Landroid/graphics/Rect;\n'
        '\n'
        '    if-eqz v1, :cond_0\n'
        '\n'
        '    iget v2, v1, Landroid/graphics/Rect;->left:I\n'
        '\n'
        '    iget v3, v1, Landroid/graphics/Rect;->top:I\n'
        '\n'
        '    iget v4, v1, Landroid/graphics/Rect;->right:I\n'
        '\n'
        '    iget v5, v1, Landroid/graphics/Rect;->bottom:I\n'
        '\n'
        '    invoke-virtual {v0, v2, v3, v4, v5}, Landroid/view/View;->layout(IIII)V\n'
        '\n'
        '    goto :cond_1\n'
        '\n'
        '    :cond_0\n'
        '    const/4 v2, 0x0\n'
        '\n'
        '    const/4 v3, 0x0\n'
        '\n'
        '    iget v4, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuWidth:I\n'
        '\n'
        '    iget v5, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuHeight:I\n'
        '\n'
        '    invoke-virtual {v0, v2, v3, v4, v5}, Landroid/view/View;->layout(IIII)V\n'
        '\n'
        '    :cond_1\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v0, :cond_3\n'
        '\n'
        '    iget-object v1, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mDomain:Lcom/coui/appcompat/poplist/PopupMenuDomain;\n'
        '\n'
        '    if-eqz v1, :cond_2\n'
        '\n'
        '    iget-object v1, v1, Lcom/coui/appcompat/poplist/PopupMenuDomain;->mSubMenu:Landroid/graphics/Rect;\n'
        '\n'
        '    if-eqz v1, :cond_2\n'
        '\n'
        '    iget v2, v1, Landroid/graphics/Rect;->left:I\n'
        '\n'
        '    iget v3, v1, Landroid/graphics/Rect;->top:I\n'
        '\n'
        '    iget v4, v1, Landroid/graphics/Rect;->right:I\n'
        '\n'
        '    iget v5, v1, Landroid/graphics/Rect;->bottom:I\n'
        '\n'
        '    invoke-virtual {v0, v2, v3, v4, v5}, Landroid/view/View;->layout(IIII)V\n'
        '\n'
        '    goto :cond_3\n'
        '\n'
        '    :cond_2\n'
        '    const/4 v2, 0x0\n'
        '\n'
        '    const/4 v3, 0x0\n'
        '\n'
        '    iget v4, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuWidth:I\n'
        '\n'
        '    iget v5, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuHeight:I\n'
        '\n'
        '    invoke-virtual {v0, v2, v3, v4, v5}, Landroid/view/View;->layout(IIII)V\n'
        '\n'
        '    :cond_3\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public onMeasure(II)V',
        '    .locals 6\n'
        '\n'
        '    const/high16 v0, 0x40000000\n'
        '\n'
        '    iget-object v1, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v1, :cond_2\n'
        '\n'
        '    iget v2, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuWidth:I\n'
        '\n'
        '    iget v3, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuHeight:I\n'
        '\n'
        '    iget-object v4, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mDomain:Lcom/coui/appcompat/poplist/PopupMenuDomain;\n'
        '\n'
        '    if-eqz v4, :cond_0\n'
        '\n'
        '    iget-object v4, v4, Lcom/coui/appcompat/poplist/PopupMenuDomain;->mMainMenu:Landroid/graphics/Rect;\n'
        '\n'
        '    if-eqz v4, :cond_0\n'
        '\n'
        '    invoke-virtual {v4}, Landroid/graphics/Rect;->width()I\n'
        '\n'
        '    move-result v5\n'
        '\n'
        '    if-lez v5, :cond_0\n'
        '\n'
        '    move v2, v5\n'
        '\n'
        '    invoke-virtual {v4}, Landroid/graphics/Rect;->height()I\n'
        '\n'
        '    move-result v5\n'
        '\n'
        '    if-lez v5, :cond_0\n'
        '\n'
        '    move v3, v5\n'
        '\n'
        '    :cond_0\n'
        '    if-lez v2, :cond_2\n'
        '\n'
        '    if-lez v3, :cond_2\n'
        '\n'
        '    invoke-static {v2, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I\n'
        '\n'
        '    move-result v2\n'
        '\n'
        '    invoke-static {v3, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I\n'
        '\n'
        '    move-result v3\n'
        '\n'
        '    invoke-virtual {v1, v2, v3}, Landroid/view/View;->measure(II)V\n'
        '\n'
        '    :cond_2\n'
        '    iget-object v1, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v1, :cond_5\n'
        '\n'
        '    iget v2, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuWidth:I\n'
        '\n'
        '    iget v3, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuHeight:I\n'
        '\n'
        '    iget-object v4, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mDomain:Lcom/coui/appcompat/poplist/PopupMenuDomain;\n'
        '\n'
        '    if-eqz v4, :cond_3\n'
        '\n'
        '    iget-object v4, v4, Lcom/coui/appcompat/poplist/PopupMenuDomain;->mSubMenu:Landroid/graphics/Rect;\n'
        '\n'
        '    if-eqz v4, :cond_3\n'
        '\n'
        '    invoke-virtual {v4}, Landroid/graphics/Rect;->width()I\n'
        '\n'
        '    move-result v5\n'
        '\n'
        '    if-lez v5, :cond_3\n'
        '\n'
        '    move v2, v5\n'
        '\n'
        '    invoke-virtual {v4}, Landroid/graphics/Rect;->height()I\n'
        '\n'
        '    move-result v5\n'
        '\n'
        '    if-lez v5, :cond_3\n'
        '\n'
        '    move v3, v5\n'
        '\n'
        '    :cond_3\n'
        '    if-lez v2, :cond_5\n'
        '\n'
        '    if-lez v3, :cond_5\n'
        '\n'
        '    invoke-static {v2, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I\n'
        '\n'
        '    move-result v2\n'
        '\n'
        '    invoke-static {v3, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I\n'
        '\n'
        '    move-result v3\n'
        '\n'
        '    invoke-virtual {v1, v2, v3}, Landroid/view/View;->measure(II)V\n'
        '\n'
        '    :cond_5\n'
        '    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I\n'
        '\n'
        '    move-result p1\n'
        '\n'
        '    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I\n'
        '\n'
        '    move-result p2\n'
        '\n'
        '    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V\n'
        '\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'protected dispatchDraw(Landroid/graphics/Canvas;)V',
        '    .locals 6\n'
        '\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v0, :cond_2\n'
        '\n'
        '    iget-object v1, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mDomain:Lcom/coui/appcompat/poplist/PopupMenuDomain;\n'
        '\n'
        '    if-eqz v1, :cond_1\n'
        '\n'
        '    iget-object v1, v1, Lcom/coui/appcompat/poplist/PopupMenuDomain;->mMainMenu:Landroid/graphics/Rect;\n'
        '\n'
        '    if-eqz v1, :cond_1\n'
        '\n'
        '    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I\n'
        '\n'
        '    move-result v2\n'
        '\n'
        '    iget v3, v1, Landroid/graphics/Rect;->left:I\n'
        '\n'
        '    int-to-float v3, v3\n'
        '\n'
        '    iget v4, v1, Landroid/graphics/Rect;->top:I\n'
        '\n'
        '    int-to-float v4, v4\n'
        '\n'
        '    invoke-virtual {p1, v3, v4}, Landroid/graphics/Canvas;->translate(FF)V\n'
        '\n'
        '    invoke-virtual {v0, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V\n'
        '\n'
        '    invoke-virtual {p1, v2}, Landroid/graphics/Canvas;->restoreToCount(I)V\n'
        '\n'
        '    goto :cond_2\n'
        '\n'
        '    :cond_1\n'
        '    invoke-virtual {v0, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V\n'
        '\n'
        '    :cond_2\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v0, :cond_4\n'
        '\n'
        '    iget-object v1, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mDomain:Lcom/coui/appcompat/poplist/PopupMenuDomain;\n'
        '\n'
        '    if-eqz v1, :cond_3\n'
        '\n'
        '    iget-object v1, v1, Lcom/coui/appcompat/poplist/PopupMenuDomain;->mSubMenu:Landroid/graphics/Rect;\n'
        '\n'
        '    if-eqz v1, :cond_3\n'
        '\n'
        '    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I\n'
        '\n'
        '    move-result v2\n'
        '\n'
        '    iget v3, v1, Landroid/graphics/Rect;->left:I\n'
        '\n'
        '    int-to-float v3, v3\n'
        '\n'
        '    iget v4, v1, Landroid/graphics/Rect;->top:I\n'
        '\n'
        '    int-to-float v4, v4\n'
        '\n'
        '    invoke-virtual {p1, v3, v4}, Landroid/graphics/Canvas;->translate(FF)V\n'
        '\n'
        '    invoke-virtual {v0, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V\n'
        '\n'
        '    invoke-virtual {p1, v2}, Landroid/graphics/Canvas;->restoreToCount(I)V\n'
        '\n'
        '    goto :cond_4\n'
        '\n'
        '    :cond_3\n'
        '    invoke-virtual {v0, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V\n'
        '\n'
        '    :cond_4\n'
        '    return-void\n',
    )
    fixed = _replace_smali_method(
        fixed,
        'public showMainMenu()V',
        '    .locals 2\n'
        '\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mMainMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-nez v0, :cond_0\n'
        '\n'
        '    return-void\n'
        '\n'
        '    :cond_0\n'
        '    const/4 v1, 0x0\n'
        '\n'
        '    invoke-virtual {p0, v1}, Landroid/view/View;->setWillNotDraw(Z)V\n'
        '\n'
        '    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V\n'
        '\n'
        '    const/high16 v1, 0x3f800000\n'
        '\n'
        '    invoke-virtual {p0, v1}, Landroid/view/View;->setAlpha(F)V\n'
        '\n'
        '    invoke-virtual {p0, v1}, Landroid/view/View;->setScaleX(F)V\n'
        '\n'
        '    invoke-virtual {p0, v1}, Landroid/view/View;->setScaleY(F)V\n'
        '\n'
        '    invoke-virtual {v0, v1}, Landroid/view/View;->setAlpha(F)V\n'
        '\n'
        '    invoke-virtual {v0, v1}, Landroid/view/View;->setScaleX(F)V\n'
        '\n'
        '    invoke-virtual {v0, v1}, Landroid/view/View;->setScaleY(F)V\n'
        '\n'
        '    iget-object v0, p0, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->mSubMenuRootView:Landroid/view/ViewGroup;\n'
        '\n'
        '    if-eqz v0, :cond_1\n'
        '\n'
        '    const/4 v1, 0x1\n'
        '\n'
        '    invoke-virtual {p0, v1}, Lcom/coui/appcompat/poplist/COUIPopupMenuRootView;->hideSubMenu(Z)V\n'
        '\n'
        '    :cond_1\n'
        '    return-void\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_oplus_camera_system_properties(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    for smali in Path(tmp_dir).glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8')
        fixed = data
        for old, new in {
            'Lcom/oplus/wrapper/os/SystemProperties;': 'Landroid/os/SystemProperties;',
            'Lcom/oplus/wrapper/os/UserHandle;': 'Landroid/os/UserHandle;',
            'Lcom/oplus/wrapper/os/Trace;': 'Landroid/os/Trace;',
            'Lcom/oplus/wrapper/os/Debug;': 'Landroid/os/Debug;',
        }.items():
            fixed = fixed.replace(old, new)
        if fixed != data:
            smali.write_text(fixed, encoding='utf-8')


def blob_fixup_melody_repackaging_detector(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    # In Melody (com.oplus.melody), the built-in raw earphone whitelist (R.raw.melody_app_whitelist)
    # is encrypted with AES-256-GCM using the SHA-256 hash of the OEM signing certificate.
    # When the APK is re-signed with ROM platform/test keys, RepackagingDetector returns the
    # hash of the new key, causing decryption to fail and resulting in an empty device feature list.
    # We patch every RepackagingDetector signature-hash getter to always return the original stock
    # certificate hash, and the LSPatch check to return false.
    key_body = (
        '    .locals 1\n'
        '\n'
        '    const/16 v0, 0x20\n'
        '\n'
        '    new-array v0, v0, [B\n'
        '\n'
        '    fill-array-data v0, :array_0\n'
        '\n'
        '    return-object v0\n'
        '\n'
        '    :array_0\n'
        '    .array-data 1\n'
        '        -0x50t\n'
        '        -0x57t\n'
        '        -0x45t\n'
        '        -0x4t\n'
        '        0x5t\n'
        '        -0x12t\n'
        '        -0x1bt\n'
        '        -0x19t\n'
        '        -0x30t\n'
        '        -0x5et\n'
        '        -0x37t\n'
        '        0x7ct\n'
        '        0x3t\n'
        '        0x5t\n'
        '        -0x7at\n'
        '        -0x1ft\n'
        '        0x5bt\n'
        '        -0x4dt\n'
        '        0x30t\n'
        '        0x11t\n'
        '        0x52t\n'
        '        0x7t\n'
        '        -0x71t\n'
        '        0x54t\n'
        '        0x47t\n'
        '        0x3bt\n'
        '        -0x48t\n'
        '        0x2dt\n'
        '        -0xat\n'
        '        -0x28t\n'
        '        -0x38t\n'
        '        0x18t\n'
        '    .end array-data\n'
    )
    lspatch_body = (
        '    .locals 1\n'
        '\n'
        '    const/4 v0, 0x0\n'
        '\n'
        '    return v0\n'
    )

    # RepackagingDetector is obfuscated (16.0.8: L.b/c(MelodyApplication)[B + L.d(...)Z;
    # 16.0.10: X.b/c/d(Context)[B + X.e(Context)Z), so locate it by its log tag and pick
    # methods by shape: every static (Context|*Application)[B getter returns the stock hash,
    # and the static (Context|*Application)Z LSPatch check (identified by its "lspatch"
    # asset probe, or an already-patched body) returns false.
    param = r'(?:Landroid/content/Context;|L[^;()]*Application;)'
    method_re = re.compile(
        rf'(?ms)^\.method ((?:public |private |protected )?(?:final )?static (?:synthetic )?'
        rf'[\w$]+\({param}\)(\[B|Z))\n(.*?)^\.end method'
    )

    candidates = []
    for smali in Path(tmp_dir).glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8')
        if '"RepackagingDetector' not in data and '.source "RepackagingDetector.java"' not in data:
            continue
        hash_sigs = []
        lspatch_sigs = []
        for m in method_re.finditer(data):
            sig, ret, body = m.group(1), m.group(2), m.group(3)
            if ret == '[B':
                hash_sigs.append(sig)
            elif '"lspatch"' in body or body == lspatch_body:
                lspatch_sigs.append(sig)
        if hash_sigs and lspatch_sigs:
            candidates.append((smali, data, hash_sigs, lspatch_sigs))

    if len(candidates) != 1:
        raise ValueError(
            'Melody.apk RepackagingDetector class not found exactly once '
            f'(found {len(candidates)}: {[str(c[0]) for c in candidates]})'
        )

    smali, data, hash_sigs, lspatch_sigs = candidates[0]
    patched = data
    for sig in hash_sigs:
        patched = _replace_smali_method(patched, sig, key_body)
    for sig in lspatch_sigs:
        patched = _replace_smali_method(patched, sig, lspatch_body)
    if patched != data:
        smali.write_text(patched, encoding='utf-8')


def blob_fixup_oplus_camera_framework_shims(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    for smali in Path(tmp_dir).glob('smali*/**/*.smali'):
        data = smali.read_text(encoding='utf-8')
        fixed = data
        for old_tag, new_tag in {
            'com.oplus.capture.flash.need': 'com.oplus.flashtrigger.state',
            'com.oplus.flash.status': 'com.oplus.flashtrigger.state',
            'com.oplus.outflash.flashtype': 'com.oplus.flashtrigger.state',
            'com.oplus.preview.outflash.connected': 'com.oplus.flashtrigger.state',
            'com.oplus.flash.IntensityControl': 'com.oplus.flashtrigger.state',
            'com.oplus.facebeauty.custom': 'com.oplus.facebeauty.level',
            'com.oplus.aec.customAE.enable': 'com.oplus.macro.closeup.enable',
            'com.oplus.DolIsStaggerState': 'com.oplus.capture.request.idx',
            'com.oplus.iris.aperture.switching': 'com.oplus.capture.request.idx',
            'com.oplus.isRawMax': 'com.oplus.capture.request.idx',
            'com.oplus.is.master.mode': 'com.oplus.capture.request.idx',
            'com.oplus.control.face.dr': 'com.oplus.capture.request.idx',
            'com.oplus.fallback.stable': 'com.oplus.capture.request.idx',
            'com.oplus.capture.job.type': 'com.oplus.capture.request.idx',
            'com.oplus.capture.request.need.preview.stream': 'com.oplus.capture.request.idx',
            'com.oplus.filter.mode': 'com.oplus.capture.request.idx',
            'com.oplus.app.filter.type': 'com.oplus.capture.request.idx',
            'com.oplus.aicolor.rear.enable': 'com.oplus.capture.request.idx',
            'com.oplus.camera.3d.api.state': 'com.oplus.capture.request.idx',
            'com.oplus.camera.configure.thermal.level': 'com.oplus.capture.request.idx',
            'com.oplus.camera.pi.enable': 'com.oplus.capture.request.idx',
            'com.oplus.camera.pi.enable_list': 'com.oplus.capture.request.idx',
            'com.oplus.asd.hdr.scope': 'com.oplus.capture.request.idx',
            'com.oplus.night.se.enable': 'com.oplus.capture.request.idx',
            'com.oplus.preview.ai.preset.asd.enable': 'com.oplus.capture.request.idx',
            'com.oplus.lsd.enable': 'com.oplus.capture.request.idx',
            'com.oplus.only.zoom.change': 'com.oplus.capture.request.idx',
            'com.oplus.config.aeExposureCompensation': 'com.oplus.capture.request.idx',
            'com.oplus.naturetone.state': 'com.oplus.capture.request.idx',
            'com.oplus.hal.fluency': 'com.oplus.capture.request.idx',
            'com.oplus.double.ois.wirecutoff.detection.sn': 'com.oplus.capture.request.idx',
            'com.oplus.process.pid': 'com.oplus.capture.request.idx',
            'com.oplus.TR.processing.state': 'com.oplus.capture.request.idx',
            'com.oplus.capture.request.idx_list': 'com.oplus.capture.request.idx',
            'com.oplus.capture.request.picture.size.scale': 'com.oplus.capture.request.idx',
            'com.oplus.picture.offset.time': 'com.oplus.capture.request.idx',
            'com.oplus.izoom.ability.support': 'com.oplus.aps.zoom.feature',
            'com.oplus.mipiraw.online.bpc': 'com.oplus.capture.mipiraw.online.bpc',
            'com.oplus.full.bining.qbc.enable': 'com.oplus.camera.is.from.main.menu',
            'com.oplus.rear.remosaic.enable': 'com.oplus.camera.is.from.main.menu',
            'com.oplus.burst.capture.single': 'com.oplus.camera.is.from.main.menu',
            'com.oplus.defer.force.start': 'com.oplus.camera.is.from.main.menu',
            'com.oplus.flash.snapshot.use.nonzsl': 'com.oplus.camera.is.from.main.menu',
            'com.oplus.algo.visualization.enable': 'com.oplus.multiobj.info.visualization',
            'com.oplus.camera.algo.visualization.enable': 'com.oplus.multiobj.info.visualization',
            'com.oplus.sod.enable': 'com.oplus.sod.touch.region',
            'com.oplus.caller.package.name': 'com.oplus.packageName',
            'com.oplus.device.orientation': 'com.oplus.preview.orientation',
        }.items():
            fixed = fixed.replace(old_tag, new_tag)
        fixed = re.sub(
            r'(?m)^\.implements Ljava/lang/Object;\n',
            '',
            fixed,
        )
        fixed = re.sub(
            r'(?m)^(\s*)invoke-virtual \{([vp]\d+)\}, Ljava/lang/Enum;->name\(\)Ljava/lang/String;',
            r'\1invoke-static {\2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;',
            fixed,
        )
        if smali.match('*/com/oplus/camera/CameraManager$a.smali'):
            fixed = fixed.replace(
                '    invoke-virtual {p0}, Landroid/os/AsyncTask;->isCancelled()Z\n'
                '\n'
                '    .line 29\n'
                '    .line 30\n'
                '    .line 31\n'
                '    move-result p1\n'
                '\n'
                '    .line 32\n'
                '    if-nez p1, :cond_4\n'
                '\n'
                '    .line 33\n'
                '    .line 34\n'
                '    sget p1, Lqk/p;->p:I\n',
                '    invoke-virtual {p0}, Landroid/os/AsyncTask;->isCancelled()Z\n'
                '\n'
                '    .line 29\n'
                '    .line 30\n'
                '    .line 31\n'
                '    move-result p1\n'
                '\n'
                '    .line 32\n'
                '    if-nez p1, :cond_4\n'
                '\n'
                '    .line 33\n'
                '    .line 34\n'
                '    const/4 p1, 0x0\n',
                1,
            )

        if smali.match('*/in/x0.smali'):
            fixed = _noop_smali_method(fixed, 'public final S6()V')

        if smali.name == 'Performance.smali':
            fixed = _noop_smali_method(fixed, 'public static setIOPriority(I)V')
            fixed = _noop_smali_method(fixed, 'private static synthetic lambda$registerOsenseEventCallback$44()V')
            fixed = _noop_smali_method(fixed, 'private static registerOsenseEventCallback()V')
            fixed = _noop_smali_method(fixed, 'private static unregisterOsenseEventCallback()V')
            fixed = _noop_smali_method(fixed, 'public static requestLongTimeTaskMode()V')
            fixed = _noop_smali_method(fixed, 'public static cancelLongTimeTaskMode()V')

        if False and smali.match('*/com/oplus/ocs/camera/CameraUnitImpl$4.smali'):
            fixed = _noop_smali_method(fixed, 'public run()V')

        if False and smali.match('*/com/oplus/ocs/camera/CameraUnitImpl.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public isAuthedClient(Landroid/content/Context;)Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x1\n'
                '\n'
                '    return v0\n',
            )

        if smali.match('*/com/oplus/aiunit/configuration/OSRepository.smali'):
            empty_map_body = _empty_map_smali_body()
            for signature in (
                'private final listFilesFromOS(Ljava/lang/String;Ljava/lang/String;)Ljava/util/Map;',
                'public static synthetic listFilesFromOS$default(Lcom/oplus/aiunit/configuration/OSRepository;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Ljava/util/Map;',
                'private final listFilesFromOsV2(Ljava/lang/String;)Ljava/util/Map;',
                'public final listPreinstalledOap2(Landroid/content/Context;)Ljava/util/Map;',
                'public final listPreinstalledOapOaa2(Landroid/content/Context;)Ljava/util/Map;',
                'private final readFilesFromOS(Ljava/lang/String;)Ljava/util/Map;',
                'private final readFilesFromOsV2(Ljava/lang/String;)Ljava/util/Map;',
                'public final readPreInstalledOrangeResConfig()Ljava/util/Map;',
                'public final readPreInstalledUnitConfig()Ljava/util/Map;',
                'public final readPreInstalledUnitConfigV2()Ljava/util/Map;',
            ):
                fixed = _replace_smali_method(fixed, signature, empty_map_body)

        if smali.match('*/com/oplus/ocs/camera/producer/info/CameraCharacteristicsHelper.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static getCameraIdType(Ljava/lang/String;)Lcom/oplus/ocs/camera/producer/info/CameraIdType;',
                '    .locals 4\n'
                '\n'
                '    sget-object v0, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsHelper;->sCameraIdTypeMap:Ljava/util/Map;\n'
                '\n'
                '    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    check-cast v1, Lcom/oplus/ocs/camera/producer/info/CameraIdType;\n'
                '\n'
                '    if-eqz v1, :cond_0\n'
                '\n'
                '    return-object v1\n'
                '\n'
                '    :cond_0\n'
                '    const/4 v2, -0x1\n'
                '\n'
                '    const-string v3, "rear_main"\n'
                '\n'
                '    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    if-eqz v3, :cond_1\n'
                '\n'
                '    const/4 v2, 0x0\n'
                '\n'
                '    goto :goto_0\n'
                '\n'
                '    :cond_1\n'
                '    const-string v3, "front_main"\n'
                '\n'
                '    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    if-eqz v3, :cond_2\n'
                '\n'
                '    const/4 v2, 0x1\n'
                '\n'
                '    goto :goto_0\n'
                '\n'
                '    :cond_2\n'
                '    const-string v3, "rear_wide"\n'
                '\n'
                '    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    if-eqz v3, :cond_3\n'
                '\n'
                '    const/4 v2, 0x2\n'
                '\n'
                '    goto :goto_0\n'
                '\n'
                '    :cond_3\n'
                '    const-string v3, "rear_tele"\n'
                '\n'
                '    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    if-eqz v3, :cond_4\n'
                '\n'
                '    const/4 v2, 0x3\n'
                '\n'
                '    goto :goto_0\n'
                '\n'
                '    :cond_4\n'
                '    const-string v3, "rear_ultra_tele"\n'
                '\n'
                '    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    if-eqz v3, :cond_5\n'
                '\n'
                '    const/4 v2, 0x4\n'
                '\n'
                '    goto :goto_0\n'
                '\n'
                '    :cond_5\n'
                '    const-string v3, "rear_main_front_main"\n'
                '\n'
                '    invoke-virtual {v3, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    if-eqz v3, :cond_6\n'
                '\n'
                '    const/16 v2, 0x64\n'
                '\n'
                '    :cond_6\n'
                '    :goto_0\n'
                '    if-ltz v2, :cond_7\n'
                '\n'
                '    new-instance v1, Lcom/oplus/ocs/camera/producer/info/CameraIdType;\n'
                '\n'
                '    invoke-direct {v1, p0, v2}, Lcom/oplus/ocs/camera/producer/info/CameraIdType;-><init>(Ljava/lang/String;I)V\n'
                '\n'
                '    invoke-interface {v0, p0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;\n'
                '\n'
                '    sget-object p0, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsHelper;->sCameraIdArray:Landroid/util/SparseArray;\n'
                '\n'
                '    invoke-virtual {p0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V\n'
                '\n'
                '    return-object v1\n'
                '\n'
                '    :cond_7\n'
                '    const/4 p0, 0x0\n'
                '\n'
                '    return-object p0\n',
            )
            fixed = fixed.replace(
                '    .line 123\n'
                '    :goto_3\n'
                '    sget-object v12, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsWrapper;->KEY_AVAILABLE_STREAM_FPS_RANGES:Landroid/hardware/camera2/CameraCharacteristics$Key;\n',
                '    .line 123\n'
                '    :goto_3\n'
                '    const-string v13, "0"\n'
                '\n'
                '    invoke-virtual {v13, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    if-eqz v13, :cond_op15_camera_type_1\n'
                '\n'
                '    const/4 v10, 0x0\n'
                '\n'
                '    goto :cond_op15_camera_type_done\n'
                '\n'
                '    :cond_op15_camera_type_1\n'
                '    const-string v13, "1"\n'
                '\n'
                '    invoke-virtual {v13, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    if-eqz v13, :cond_op15_camera_type_2\n'
                '\n'
                '    const/4 v10, 0x1\n'
                '\n'
                '    goto :cond_op15_camera_type_done\n'
                '\n'
                '    :cond_op15_camera_type_2\n'
                '    const-string v13, "2"\n'
                '\n'
                '    invoke-virtual {v13, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    if-eqz v13, :cond_op15_camera_type_3\n'
                '\n'
                '    const/4 v10, 0x2\n'
                '\n'
                '    goto :cond_op15_camera_type_done\n'
                '\n'
                '    :cond_op15_camera_type_3\n'
                '    const-string v13, "3"\n'
                '\n'
                '    invoke-virtual {v13, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    if-eqz v13, :cond_op15_camera_type_4\n'
                '\n'
                '    const/4 v10, 0x6\n'
                '\n'
                '    goto :cond_op15_camera_type_done\n'
                '\n'
                '    :cond_op15_camera_type_4\n'
                '    const-string v13, "4"\n'
                '\n'
                '    invoke-virtual {v13, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    if-eqz v13, :cond_op15_camera_type_done\n'
                '\n'
                '    const/16 v10, 0x1a\n'
                '\n'
                '    :cond_op15_camera_type_done\n'
                '    sget-object v12, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsWrapper;->KEY_AVAILABLE_STREAM_FPS_RANGES:Landroid/hardware/camera2/CameraCharacteristics$Key;\n',
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2Impl.smali'):
            fixed = fixed.replace(
                '.method public openCameraDevice(ILandroid/os/Handler;)V\n'
                '    .locals 6\n',
                '.method public openCameraDevice(ILandroid/os/Handler;)V\n'
                '    .locals 8\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {v1, p1, v3, p2}, Landroid/hardware/camera2/CameraManager;->openCamera(Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;Landroid/os/Handler;)V\n'
                '\n'
                '    .line 2919\n',
                '    const-string v6, "OP15Unit"\n'
                '\n'
                '    new-instance v7, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v4, "Camera2Impl openCameraDevice requested id="\n'
                '\n'
                '    invoke-direct {v7, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v7\n'
                '\n'
                '    invoke-static {v6, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v6\n'
                '\n'
                '    invoke-virtual {v1, p1, v3, p2}, Landroid/hardware/camera2/CameraManager;->openCamera(Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;Landroid/os/Handler;)V\n'
                '\n'
                '    .line 2919\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mDeviceVariable:Landroid/os/ConditionVariable;\n'
                '\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    return-void\n',
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mDeviceVariable:Landroid/os/ConditionVariable;\n'
                '\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    const-string p0, "OP15Unit"\n'
                '\n'
                '    const-string p1, "Camera2Impl openCameraDevice block returned"\n'
                '\n'
                '    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    return-void\n',
                1,
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2Impl$2.smali'):
            fixed = fixed.replace(
                '.method public onOpened(Landroid/hardware/camera2/CameraDevice;)V\n'
                '    .locals 2\n',
                '.method public onOpened(Landroid/hardware/camera2/CameraDevice;)V\n'
                '    .locals 3\n'
                '\n'
                '    const-string v0, "OP15Unit"\n'
                '\n'
                '    new-instance v1, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, "Camera2Impl.StateCallback onOpened device="\n'
                '\n'
                '    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2StateMachineImpl$1.smali'):
            fixed = fixed.replace(
                '.method public onOpened(Landroid/hardware/camera2/CameraDevice;)V\n'
                '    .locals 1\n',
                '.method public onOpened(Landroid/hardware/camera2/CameraDevice;)V\n'
                '    .locals 2\n'
                '\n'
                '    const-string v0, "OP15Unit"\n'
                '\n'
                '    const-string v1, "StateMachine inner onOpened entry"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2StateMachineImpl$StateMachineHandler.smali'):
            fixed = fixed.replace(
                '    invoke-interface {p1, v0, v1}, Lcom/oplus/ocs/camera/producer/device/Camera2Interface;->openCameraDevice(ILandroid/os/Handler;)V\n'
                '\n'
                '    .line 375\n',
                '    invoke-interface {p1, v0, v1}, Lcom/oplus/ocs/camera/producer/device/Camera2Interface;->openCameraDevice(ILandroid/os/Handler;)V\n'
                '\n'
                '    const-string p1, "OP15Unit"\n'
                '\n'
                '    const-string v0, "StateMachine MSG_OPEN_CAMERA_DEVICE returned from openCameraDevice"\n'
                '\n'
                '    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    .line 375\n',
                1,
            )

        if smali.match('*/vj/k.smali'):
            fixed = fixed.replace(
                '    iget-object p0, p0, Lvj/k;->K:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 648\n'
                '    .line 649\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    .line 650\n',
                '    iget-object p0, p0, Lvj/k;->K:Landroid/os/ConditionVariable;\n'
                '\n'
                '    const-string v9, "OP15Preview"\n'
                '\n'
                '    new-instance v10, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v0, "J waiting K="\n'
                '\n'
                '    invoke-direct {v10, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v10\n'
                '\n'
                '    invoke-static {v9, v10}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v9\n'
                '\n'
                '    .line 648\n'
                '    .line 649\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    const-string v9, "OP15Preview"\n'
                '\n'
                '    const-string v10, "J released K"\n'
                '\n'
                '    invoke-static {v9, v10}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v9\n'
                '\n'
                '    .line 650\n',
                1,
            )

        if smali.match('*/com/oplus/camera/Camera$h.smali'):
            fixed = fixed.replace(
                '.method public final onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V\n'
                '    .locals 3\n',
                '.method public final onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V\n'
                '    .locals 3\n'
                '\n'
                '    const-string v0, "OP15ApsBind"\n'
                '\n'
                '    const-string v1, "Camera$h onServiceConnected entry"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p1, p0, Lcom/oplus/camera/CameraManager;->J:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 106\n'
                '    .line 107\n'
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    .line 108\n',
                '    iget-object p1, p0, Lcom/oplus/camera/CameraManager;->J:Landroid/os/ConditionVariable;\n'
                '\n'
                '    const-string p2, "OP15ApsBind"\n'
                '\n'
                '    const-string v0, "Camera$h waiting CameraManager.J"\n'
                '\n'
                '    invoke-static {p2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p2\n'
                '\n'
                '    .line 106\n'
                '    .line 107\n'
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    const-string p1, "OP15ApsBind"\n'
                '\n'
                '    const-string p2, "Camera$h CameraManager.J released"\n'
                '\n'
                '    invoke-static {p1, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    .line 108\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p1, p1, Lvj/k;->K:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 120\n'
                '    .line 121\n'
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    .line 122\n',
                '    iget-object p1, p1, Lvj/k;->K:Landroid/os/ConditionVariable;\n'
                '\n'
                '    const-string v0, "OP15Preview"\n'
                '\n'
                '    new-instance p2, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v1, "Camera$h opening K="\n'
                '\n'
                '    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-static {p1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I\n'
                '\n'
                '    move-result v1\n'
                '\n'
                '    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object p2\n'
                '\n'
                '    invoke-static {v0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    .line 120\n'
                '    .line 121\n'
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    .line 122\n',
                1,
            )

        if smali.match('*/com/oplus/camera/Camera$i.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 4\n',
                '.method public final run()V\n'
                '    .locals 4\n'
                '\n'
                '    const-string v0, "OP15ApsBind"\n'
                '\n'
                '    const-string v1, "Camera$i bind runnable entry"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )
            fixed = fixed.replace(
                '    sget-object v2, Lcom/oplus/camera/MyApplication;->d:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 51\n'
                '    .line 52\n'
                '    invoke-virtual {v2}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    .line 53\n',
                '    const-string v2, "OP15ApsBind"\n'
                '\n'
                '    const-string v3, "Camera$i skip MyApplication.d wait before APS bind"\n'
                '\n'
                '    invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v2\n'
                '\n'
                '    .line 53\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {p0, v0, v1, v2, v3}, Landroid/content/Context;->bindService(Landroid/content/Intent;ILjava/util/concurrent/Executor;Landroid/content/ServiceConnection;)Z\n'
                '\n'
                '    .line 75\n',
                '    invoke-virtual {p0, v0, v1, v2, v3}, Landroid/content/Context;->bindService(Landroid/content/Intent;ILjava/util/concurrent/Executor;Landroid/content/ServiceConnection;)Z\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    const-string v1, "OP15ApsBind"\n'
                '\n'
                '    new-instance v2, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, "Camera$i bindService result="\n'
                '\n'
                '    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v0\n'
                '\n'
                '    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    .line 75\n',
                1,
            )

        if False and smali.match('*/mj/r3.smali'):
            fixed = fixed.replace(
                '    invoke-virtual {p0}, Lmj/r3;->x()V\n'
                '\n'
                '    .line 24\n'
                '    .line 25\n'
                '    .line 26\n'
                '    return-void\n',
                '    invoke-virtual {p0}, Lmj/r3;->x()V\n'
                '\n'
                '    iget-object v0, p0, Lmj/r3;->L:Lvj/k;\n'
                '\n'
                '    if-eqz v0, :cond_op15_c0_k_done\n'
                '\n'
                '    iget-object v0, v0, Lvj/k;->K:Landroid/os/ConditionVariable;\n'
                '\n'
                '    if-eqz v0, :cond_op15_c0_k_done\n'
                '\n'
                '    const-string v1, "OP15Preview"\n'
                '\n'
                '    new-instance v2, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string p1, "r3.c0 opening K="\n'
                '\n'
                '    invoke-direct {v2, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object p1\n'
                '\n'
                '    invoke-static {v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    invoke-virtual {v0}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    :cond_op15_c0_k_done\n'
                '    .line 24\n'
                '    .line 25\n'
                '    .line 26\n'
                '    return-void\n',
                1,
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2Impl.smali'):
            fixed = fixed.replace(
                '    .line 2976\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mDeviceVariable:Landroid/os/ConditionVariable;\n'
                '\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n',
                '    .line 2976\n'
                '    invoke-direct {p0}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->closeAllImageReader()V\n'
                '\n'
                '    iget-object v1, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mCameraStateCallback:Landroid/hardware/camera2/CameraDevice$StateCallback;\n'
                '\n'
                '    if-eqz v1, :cond_op15_direct_closed_callback\n'
                '\n'
                '    iget-object v2, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mCameraDevice:Landroid/hardware/camera2/CameraDevice;\n'
                '\n'
                '    invoke-virtual {v1, v2}, Landroid/hardware/camera2/CameraDevice$StateCallback;->onClosed(Landroid/hardware/camera2/CameraDevice;)V\n'
                '\n'
                '    :cond_op15_direct_closed_callback\n'
                '    iget-object v1, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mDeviceVariable:Landroid/os/ConditionVariable;\n'
                '\n'
                '    invoke-virtual {v1}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    const/4 v1, 0x0\n'
                '\n'
                '    iput-object v1, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->mCameraDevice:Landroid/hardware/camera2/CameraDevice;\n',
            )
            fixed = fixed.replace(
                '    if-nez v1, :cond_0\n'
                '\n'
                '    return-void\n'
                '\n'
                '    .line 2905\n'
                '    :cond_0\n'
                '    invoke-virtual {p0, v1}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->updateOplusParams(Landroid/hardware/camera2/CameraManager;)V\n',
                '    if-nez v1, :cond_0\n'
                '\n'
                '    return-void\n'
                '\n'
                '    .line 2905\n'
                '    :cond_0\n'
                '    const/16 v2, 0x64\n'
                '\n'
                '    if-ne p1, v2, :cond_0_op15_real_id\n'
                '\n'
                '    const/4 p1, 0x0\n'
                '\n'
                '    :cond_0_op15_real_id\n'
                '    invoke-virtual {p0, v1}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->updateOplusParams(Landroid/hardware/camera2/CameraManager;)V\n',
            )
        if smali.match('*/com/oplus/ocs/camera/producer/device/Camera2Impl$2.smali'):
            fixed = fixed.replace(
                '.method public onClosed(Landroid/hardware/camera2/CameraDevice;)V\n'
                '    .locals 2\n',
                '.method public onClosed(Landroid/hardware/camera2/CameraDevice;)V\n'
                '    .locals 3\n',
            )
            fixed = fixed.replace(
                '    const-string v1, "StateCallback"\n'
                '\n'
                '    invoke-static {v1, v0}, Lcom/oplus/ocs/camera/common/util/CameraUnitLog;->w(Ljava/lang/String;Ljava/lang/String;)V\n'
                '\n'
                '    .line 350\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$2;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n',
                '    const-string v1, "StateCallback"\n'
                '\n'
                '    invoke-static {v1, v0}, Lcom/oplus/ocs/camera/common/util/CameraUnitLog;->w(Ljava/lang/String;Ljava/lang/String;)V\n'
                '\n'
                '    iget-object v2, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$2;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n'
                '\n'
                '    invoke-static {v2}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->-$$Nest$fgetmCameraStateCallback(Lcom/oplus/ocs/camera/producer/device/Camera2Impl;)Landroid/hardware/camera2/CameraDevice$StateCallback;\n'
                '\n'
                '    move-result-object v2\n'
                '\n'
                '    if-eqz v2, :cond_op15_on_closed_forwarded\n'
                '\n'
                '    invoke-virtual {v2, p1}, Landroid/hardware/camera2/CameraDevice$StateCallback;->onClosed(Landroid/hardware/camera2/CameraDevice;)V\n'
                '\n'
                '    :cond_op15_on_closed_forwarded\n'
                '    .line 350\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$2;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n',
            )
        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2Impl$12.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public execute(Ljava/lang/Runnable;)V',
                '    .locals 0\n'
                '\n'
                '    invoke-interface {p1}, Ljava/lang/Runnable;->run()V\n'
                '\n'
                '    return-void\n',
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/Camera2Impl$7.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public onConfigured(Landroid/hardware/camera2/CameraCaptureSession;)V',
                '    .locals 3\n'
                '\n'
                '    .line 838\n'
                '    new-instance v0, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v1, "onConfigured,"\n'
                '\n'
                '    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v0\n'
                '\n'
                '    const-string v1, "StateCallback"\n'
                '\n'
                '    invoke-static {v1, v0}, Lcom/oplus/ocs/camera/common/util/CameraUnitLog;->w(Ljava/lang/String;Ljava/lang/String;)V\n'
                '\n'
                '    const-string v0, "CameraUnit.CameraStartupPerformance.onCameraCaptureSessionConfigured"\n'
                '\n'
                '    .line 840\n'
                '    invoke-static {v0}, Lcom/oplus/ocs/camera/common/util/CameraUnitLog;->traceBeginSection(Ljava/lang/String;)V\n'
                '\n'
                '    .line 842\n'
                '    iget-object v1, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$7;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n'
                '\n'
                '    invoke-static {v1, p1}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->-$$Nest$fputmCaptureSession(Lcom/oplus/ocs/camera/producer/device/Camera2Impl;Landroid/hardware/camera2/CameraCaptureSession;)V\n'
                '\n'
                '    move-object v2, p1\n'
                '\n'
                '    .line 843\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$7;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n'
                '\n'
                '    invoke-static {p1}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->-$$Nest$fgetmSessionVariable(Lcom/oplus/ocs/camera/producer/device/Camera2Impl;)Landroid/os/ConditionVariable;\n'
                '\n'
                '    move-result-object p1\n'
                '\n'
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$7;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n'
                '\n'
                '    invoke-static {p1}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->-$$Nest$fgetmCameraSessionCallback(Lcom/oplus/ocs/camera/producer/device/Camera2Impl;)Landroid/hardware/camera2/CameraCaptureSession$StateCallback;\n'
                '\n'
                '    move-result-object p1\n'
                '\n'
                '    if-eqz p1, :cond_0_op15_config_forwarded\n'
                '\n'
                '    invoke-virtual {p1, v2}, Landroid/hardware/camera2/CameraCaptureSession$StateCallback;->onConfigured(Landroid/hardware/camera2/CameraCaptureSession;)V\n'
                '\n'
                '    :cond_0_op15_config_forwarded\n'
                '    .line 844\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/producer/device/Camera2Impl$7;->this$0:Lcom/oplus/ocs/camera/producer/device/Camera2Impl;\n'
                '\n'
                '    const/4 p1, 0x0\n'
                '\n'
                '    invoke-static {p0, p1}, Lcom/oplus/ocs/camera/producer/device/Camera2Impl;->-$$Nest$fputmbNotAllowedTakePicture(Lcom/oplus/ocs/camera/producer/device/Camera2Impl;Z)V\n'
                '\n'
                '    .line 846\n'
                '    invoke-static {v0}, Lcom/oplus/ocs/camera/common/util/CameraUnitLog;->traceEndSection(Ljava/lang/String;)V\n'
                '\n'
                '    return-void\n',
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/device/CameraSessionEntity.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public getOperationMode()I',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )
            fixed = _replace_smali_method(
                fixed,
                'public setOperationMode(Ljava/lang/String;)V',
                '    .locals 1\n'
                '\n'
                '    const-string v0, "0"\n'
                '\n'
                '    iput-object v0, p0, Lcom/oplus/ocs/camera/producer/device/CameraSessionEntity;->mOperationMode:Ljava/lang/String;\n'
                '\n'
                '    return-void\n',
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter.smali'):
            fixed = fixed.replace(
                '    .line 1508\n'
                '    :goto_1\n'
                '    invoke-static {}, Lcom/oplus/ocs/camera/platform/PlatformUtil;->getPlatformFlag()Ljava/lang/String;\n',
                '    .line 1508\n'
                '    :goto_1\n'
                '    const-string p1, "OP15Retry"\n'
                '\n'
                '    const-string v0, "onCameraOpened retryPendingPreview"\n'
                '\n'
                '    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->this$0:Lcom/oplus/ocs/camera/producer/ProducerImpl;\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mHandler:Landroid/os/Handler;\n'
                '\n'
                '    invoke-virtual {p1, v0}, Lcom/oplus/ocs/camera/producer/ProducerImpl;->retryPendingPreview(Landroid/os/Handler;)V\n'
                '\n'
                '    invoke-static {}, Lcom/oplus/ocs/camera/platform/PlatformUtil;->getPlatformFlag()Ljava/lang/String;\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    .line 1661\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mHandler:Landroid/os/Handler;\n',
                '    invoke-virtual {p1}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->this$0:Lcom/oplus/ocs/camera/producer/ProducerImpl;\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mHandler:Landroid/os/Handler;\n'
                '\n'
                '    invoke-virtual {p1, v0}, Lcom/oplus/ocs/camera/producer/ProducerImpl;->retryPendingPreview(Landroid/os/Handler;)V\n'
                '\n'
                '    .line 1661\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mHandler:Landroid/os/Handler;\n',
            )

        if False and smali.match('*/com/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter.smali'):
            fixed = fixed.replace(
                '    .line 1497\n'
                '    :try_start_3\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mHandler:Landroid/os/Handler;\n'
                '\n'
                '    if-eqz p1, :cond_6\n'
                '\n'
                '    .line 1498\n'
                '    new-instance v0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter$1;\n'
                '\n'
                '    invoke-direct {v0, p0}, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter$1;-><init>(Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;)V\n'
                '\n'
                '    invoke-virtual {p1, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z\n'
                '\n'
                '    goto :goto_1\n'
                '\n'
                '    .line 1505\n'
                '    :cond_6\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mCameraStateCallbackAdapter:Lcom/oplus/ocs/camera/appinterface/CameraStateCallbackAdapter;\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->this$0:Lcom/oplus/ocs/camera/producer/ProducerImpl;\n'
                '\n'
                '    invoke-virtual {p1, v0}, Lcom/oplus/ocs/camera/appinterface/CameraStateCallbackAdapter;->onCameraOpened(Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;)V\n'
                '\n'
                '    .line 1508\n'
                '    :goto_1\n',
                '    .line 1497\n'
                '    :try_start_3\n'
                '    const-string p1, "OP15Unit"\n'
                '\n'
                '    const-string v0, "DefaultAdapter direct onCameraOpened callback"\n'
                '\n'
                '    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    iget-object p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->mCameraStateCallbackAdapter:Lcom/oplus/ocs/camera/appinterface/CameraStateCallbackAdapter;\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl$DefaultCameraStateCallbackAdapter;->this$0:Lcom/oplus/ocs/camera/producer/ProducerImpl;\n'
                '\n'
                '    invoke-virtual {p1, v0}, Lcom/oplus/ocs/camera/appinterface/CameraStateCallbackAdapter;->onCameraOpened(Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;)V\n'
                '\n'
                '    .line 1508\n'
                '    :goto_1\n',
                1,
            )

        if smali.match('*/com/oplus/ocs/camera/producer/ProducerImpl.smali'):
            fixed = fixed.replace(
                '    .line 139\n'
                '    iput-boolean p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl;->mbManageMultiDevice:Z\n',
                '    .line 139\n'
                '    const/4 p1, 0x0\n'
                '\n'
                '    iput-boolean p1, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl;->mbManageMultiDevice:Z\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {v0}, Lcom/oplus/ocs/camera/producer/device/CameraSessionEntity;->getOperationMode()I\n'
                '\n'
                '    move-result p5\n',
                '    invoke-virtual {v0}, Lcom/oplus/ocs/camera/producer/device/CameraSessionEntity;->getOperationMode()I\n'
                '\n'
                '    move-result p5\n'
                '\n'
                '    const/4 p5, 0x0\n',
                1,
            )
            fixed = _replace_smali_method(
                fixed,
                'public setParameter(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)V',
                '    .locals 1\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl;->mAllStageParameterBuilder:Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;\n'
                '\n'
                '    if-nez v0, :cond_0\n'
                '\n'
                '    new-instance v0, Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;\n'
                '\n'
                '    invoke-direct {v0}, Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;-><init>()V\n'
                '\n'
                '    iput-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl;->mAllStageParameterBuilder:Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;\n'
                '\n'
                '    :cond_0\n'
                '    invoke-virtual {v0, p1, p2}, Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;->set(Landroid/hardware/camera2/CaptureRequest$Key;Ljava/lang/Object;)Lcom/oplus/ocs/camera/metadata/parameter/Parameter$BaseBuilder;\n'
                '\n'
                '    return-void\n',
            )
            fixed = _replace_smali_method(
                fixed,
                'public setParameter(Ljava/lang/String;Ljava/lang/Object;)V',
                '    .locals 1\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl;->mAllStageParameterBuilder:Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;\n'
                '\n'
                '    if-nez v0, :cond_0\n'
                '\n'
                '    new-instance v0, Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;\n'
                '\n'
                '    invoke-direct {v0}, Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;-><init>()V\n'
                '\n'
                '    iput-object v0, p0, Lcom/oplus/ocs/camera/producer/ProducerImpl;->mAllStageParameterBuilder:Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;\n'
                '\n'
                '    :cond_0\n'
                '    invoke-virtual {v0, p1, p2}, Lcom/oplus/ocs/camera/metadata/parameter/PreviewParameter$Builder;->set(Ljava/lang/String;Ljava/lang/Object;)Lcom/oplus/ocs/camera/metadata/parameter/Parameter$BaseBuilder;\n'
                '\n'
                '    return-void\n',
            )
            # Keep original null-current-mode behavior instead of silently creating
            # a rear photo mode during switch/startPreview.

        if smali.match('*/wl/h.smali'):
            fixed = _noop_smali_method(fixed, 'public final run()V')

        if smali.match('*/nj/d.smali'):
            fixed = fixed.replace(
                '.method public final g7(II)V\n'
                '    .locals 6\n',
                '.method public final g7(II)V\n'
                '    .locals 6\n'
                '\n'
                '    const-string v0, "OP15Switch"\n'
                '\n'
                '    new-instance v1, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, "g7 target="\n'
                '\n'
                '    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, " openType="\n'
                '\n'
                '    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, " paused="\n'
                '\n'
                '    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    iget-boolean v2, p0, Lnj/d;->d:Z\n'
                '\n'
                '    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, " switching="\n'
                '\n'
                '    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    iget-boolean v2, p0, Lnj/d;->e:Z\n'
                '\n'
                '    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )

        if smali.match('*/uj/g.smali'):
            fixed = fixed.replace(
                '.method public final n(IZ)Z\n'
                '    .locals 6\n',
                '.method public final n(IZ)Z\n'
                '    .locals 8\n'
                '\n'
                '    const-string v0, "OP15Switch"\n'
                '\n'
                '    new-instance v1, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, "DeviceProcessor.n entry arg="\n'
                '\n'
                '    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, " flag="\n'
                '\n'
                '    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-interface {v2}, Lcom/oplus/camera/b;->a()Z\n'
                '\n'
                '    .line 70\n'
                '    .line 71\n'
                '    .line 72\n'
                '    move-result v0\n'
                '\n'
                '    .line 73\n',
                '    invoke-interface {v2}, Lcom/oplus/camera/b;->a()Z\n'
                '\n'
                '    .line 70\n'
                '    .line 71\n'
                '    .line 72\n'
                '    move-result v0\n'
                '\n'
                '    const-string v6, "OP15Switch"\n'
                '\n'
                '    new-instance v7, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, "DeviceProcessor.n active="\n'
                '\n'
                '    invoke-direct {v7, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, " openType="\n'
                '\n'
                '    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v7\n'
                '\n'
                '    invoke-static {v6, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v6\n'
                '\n'
                '    const-string v3, "DeviceProcessor"\n'
                '\n'
                '    .line 73\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-interface {p1}, Ls7/x$h;->Y()J\n'
                '\n'
                '    .line 82\n'
                '    .line 83\n'
                '    .line 84\n'
                '    move-result-wide v4\n'
                '\n'
                '    .line 85\n',
                '    invoke-interface {p1}, Ls7/x$h;->Y()J\n'
                '\n'
                '    .line 82\n'
                '    .line 83\n'
                '    .line 84\n'
                '    move-result-wide v4\n'
                '\n'
                '    const-string v6, "OP15Switch"\n'
                '\n'
                '    new-instance v7, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string p1, "DeviceProcessor.n delay="\n'
                '\n'
                '    invoke-direct {v7, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v7, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v7\n'
                '\n'
                '    invoke-static {v6, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v6\n'
                '\n'
                '    .line 85\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-interface {p1, v4, v5, p0}, Lf6/c;->s2(JLjava/lang/Runnable;)V\n'
                '\n'
                '    .line 106\n',
                '    invoke-interface {p1, v4, v5, p0}, Lf6/c;->s2(JLjava/lang/Runnable;)V\n'
                '\n'
                '    const-string p0, "OP15Switch"\n'
                '\n'
                '    const-string p1, "DeviceProcessor.n scheduled delayed"\n'
                '\n'
                '    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 106\n',
                1,
            )
            # Keep the stock app scheduler for immediate opens. Bypassing V5().R0()
            # can open the new camera device while leaving app-side mode/UI state on
            # the old camera, which is exactly what OP15 switch logs showed.
        if smali.match('*/uj/g$c.smali'):
            fixed = fixed.replace(
                '.method public final a()V\n'
                '    .locals 5\n'
                '\n'
                '    .line 1\n'
                '    const-string v0, "DeviceProcessor"\n',
                '.method public final a()V\n'
                '    .locals 5\n'
                '\n'
                '    const-string v0, "OP15Close"\n'
                '\n'
                '    const-string v1, "DeviceProcessor.closeComplete entry"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    .line 1\n'
                '    const-string v0, "DeviceProcessor"\n',
                1,
            )
            fixed = fixed.replace(
                '    :cond_2\n'
                '    return-void\n',
                '    :cond_2\n'
                '    const-string v0, "OP15Close"\n'
                '\n'
                '    const-string v1, "DeviceProcessor.closeComplete return"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    return-void\n',
                1,
            )
            fixed = fixed.replace(
                '.method public static g(Luj/g$c;ZIZ)V\n'
                '    .locals 12\n',
                '.method public static g(Luj/g$c;ZIZ)V\n'
                '    .locals 12\n'
                '\n'
                '    const-string v10, "OP15Switch"\n'
                '\n'
                '    new-instance v11, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v0, "responseCameraOpened entry first="\n'
                '\n'
                '    invoke-direct {v11, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v11, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v0, " cameraId="\n'
                '\n'
                '    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v0, " openedPaused="\n'
                '\n'
                '    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11, p3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v11\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {p0}, Lpj/a;->d()I\n'
                '\n'
                '    .line 177\n'
                '    .line 178\n'
                '    .line 179\n'
                '    move-result p0\n'
                '\n'
                '    .line 180\n',
                '    invoke-virtual {p0}, Lpj/a;->d()I\n'
                '\n'
                '    .line 177\n'
                '    .line 178\n'
                '    .line 179\n'
                '    move-result p0\n'
                '\n'
                '    const-string v10, "OP15Switch"\n'
                '\n'
                '    new-instance v11, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v8, "responseCameraOpened taskCount="\n'
                '\n'
                '    invoke-direct {v11, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v11, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v8, " cameraId="\n'
                '\n'
                '    invoke-virtual {v11, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v11\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n'
                '\n'
                '    .line 180\n',
                1,
            )
            fixed = fixed.replace(
                '    if-eqz p0, :cond_6\n'
                '\n'
                '    .line 191\n',
                '    const-string v10, "OP15Switch"\n'
                '\n'
                '    new-instance v11, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v8, "responseCameraOpened taskInfoNull="\n'
                '\n'
                '    invoke-direct {v11, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    if-nez p0, :cond_op15_task_not_null\n'
                '\n'
                '    const/4 v8, 0x1\n'
                '\n'
                '    goto :goto_op15_task_null_done\n'
                '\n'
                '    :cond_op15_task_not_null\n'
                '    const/4 v8, 0x0\n'
                '\n'
                '    :goto_op15_task_null_done\n'
                '    invoke-virtual {v11, v8}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v11\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n'
                '\n'
                '    if-eqz p0, :cond_6\n'
                '\n'
                '    .line 191\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p0, v7, Lmj/r3;->L:Lvj/k;\n'
                '\n'
                '    .line 324\n'
                '    .line 325\n'
                '    invoke-virtual {p0, p3}, Lvj/k;->q(Z)V\n',
                '    const-string v10, "OP15Switch"\n'
                '\n'
                '    const-string v11, "responseCameraOpened calling preview q"\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n'
                '\n'
                '    iget-object p0, v7, Lmj/r3;->L:Lvj/k;\n'
                '\n'
                '    .line 324\n'
                '    .line 325\n'
                '    invoke-virtual {p0, p3}, Lvj/k;->q(Z)V\n',
                1,
            )
            fixed = fixed.replace(
                '    :cond_14\n'
                '    const-string p0, "responseCameraOpened, will create session in next task, so drop it!"\n',
                '    :cond_14\n'
                '    const-string v10, "OP15Switch"\n'
                '\n'
                '    const-string v11, "responseCameraOpened dropping for next task"\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n'
                '\n'
                '    const-string p0, "responseCameraOpened, will create session in next task, so drop it!"\n',
                1,
            )
            fixed = fixed.replace(
                '.method public final f(Lcom/oplus/ocs/camera/CameraDevice;I)V\n'
                '    .locals 8\n',
                '.method public final f(Lcom/oplus/ocs/camera/CameraDevice;I)V\n'
                '    .locals 10\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-boolean v0, p0, Luj/g;->w:Z\n'
                '\n'
                '    .line 35\n',
                '    iget-boolean v0, p0, Luj/g;->w:Z\n'
                '\n'
                '    const-string v8, "OP15Switch"\n'
                '\n'
                '    new-instance v9, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, "onCameraOpened entry cameraId="\n'
                '\n'
                '    invoke-direct {v9, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v9, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, " wasPausedOpen="\n'
                '\n'
                '    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, " openType="\n'
                '\n'
                '    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    iget v3, p0, Luj/g;->m:I\n'
                '\n'
                '    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v9\n'
                '\n'
                '    invoke-static {v8, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v8\n'
                '\n'
                '    .line 35\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {p0}, Lsj/a;->d()Z\n'
                '\n'
                '    .line 82\n'
                '    .line 83\n'
                '    .line 84\n'
                '    move-result v3\n'
                '\n'
                '    .line 85\n',
                '    invoke-virtual {p0}, Lsj/a;->d()Z\n'
                '\n'
                '    .line 82\n'
                '    .line 83\n'
                '    .line 84\n'
                '    move-result v3\n'
                '\n'
                '    new-instance v9, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v8, "onCameraOpened state isPaused="\n'
                '\n'
                '    invoke-direct {v9, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v8, " appBlocked="\n'
                '\n'
                '    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v9, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v9\n'
                '\n'
                '    const-string v8, "OP15Switch"\n'
                '\n'
                '    invoke-static {v8, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v8\n'
                '\n'
                '    .line 85\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-static {p0, v4, p2, v0}, Luj/g$c;->g(Luj/g$c;ZIZ)V\n'
                '\n'
                '    .line 564\n',
                '    const-string p1, "OP15Switch"\n'
                '\n'
                '    const-string v1, "onCameraOpened call response first=false"\n'
                '\n'
                '    invoke-static {p1, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    invoke-static {p0, v4, p2, v0}, Luj/g$c;->g(Luj/g$c;ZIZ)V\n'
                '\n'
                '    .line 564\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-static {p0, v2, p2, v0}, Luj/g$c;->g(Luj/g$c;ZIZ)V\n'
                '\n'
                '    .line 570\n',
                '    const-string p1, "OP15Switch"\n'
                '\n'
                '    const-string v1, "onCameraOpened call response first=true"\n'
                '\n'
                '    invoke-static {p1, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p1\n'
                '\n'
                '    invoke-static {p0, v2, p2, v0}, Luj/g$c;->g(Luj/g$c;ZIZ)V\n'
                '\n'
                '    .line 570\n',
                1,
            )

        if smali.match('*/s7/b1.smali'):
            fixed = fixed.replace(
                '.method public final A(Z)V\n'
                '    .locals 2\n',
                '.method public final A(Z)V\n'
                '    .locals 4\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {p0, v0}, Ls7/b1;->G(Ljava/lang/Runnable;)V\n'
                '\n'
                '    .line 36\n',
                '    const-string v2, "OP15Close"\n'
                '\n'
                '    const-string v3, "b1.A scheduling f0 close runnable"\n'
                '\n'
                '    invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v2\n'
                '\n'
                '    invoke-virtual {p0, v0}, Ls7/b1;->G(Ljava/lang/Runnable;)V\n'
                '\n'
                '    const-string v2, "OP15Close"\n'
                '\n'
                '    const-string v3, "b1.A returned from G, waiting n"\n'
                '\n'
                '    invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v2\n'
                '\n'
                '    .line 36\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    .line 47\n'
                '    .line 48\n'
                '    .line 49\n'
                '    const-string p0, "closeCameraDevice X"\n',
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    const-string p0, "OP15Close"\n'
                '\n'
                '    const-string v0, "b1.A n released"\n'
                '\n'
                '    invoke-static {p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 47\n'
                '    .line 48\n'
                '    .line 49\n'
                '    const-string p0, "closeCameraDevice X"\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {v0, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z\n'
                '\n'
                '    .line 30\n'
                '    .line 31\n'
                '    .line 32\n'
                '    return-void\n'
                '.end method',
                '    invoke-virtual {v0, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    const-string v1, "OP15Preview"\n'
                '\n'
                '    new-instance v2, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, "b1.W post result="\n'
                '\n'
                '    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, " operation="\n'
                '\n'
                '    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v2, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, " mode="\n'
                '\n'
                '    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v2, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v2\n'
                '\n'
                '    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v1\n'
                '\n'
                '    .line 30\n'
                '    .line 31\n'
                '    .line 32\n'
                '    return-void\n'
                '.end method',
                1,
            )

        if smali.match('*/s7/f0.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 7\n',
                '.method public final run()V\n'
                '    .locals 7\n'
                '\n'
                '    const-string v3, "OP15Close"\n'
                '\n'
                '    const-string v4, "f0.run entry"\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object v1, v0, Ls7/b1;->q:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 6\n'
                '    .line 7\n'
                '    invoke-virtual {v1}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    .line 8\n',
                '    iget-object v1, v0, Ls7/b1;->q:Landroid/os/ConditionVariable;\n'
                '\n'
                '    const-string v3, "OP15Close"\n'
                '\n'
                '    const-string v4, "f0 waiting q"\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    .line 6\n'
                '    .line 7\n'
                '    invoke-virtual {v1}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    const-string v3, "OP15Close"\n'
                '\n'
                '    const-string v4, "f0 q released, closing device"\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    .line 8\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-virtual {v0, v3, p0}, Lcom/oplus/ocs/camera/CameraDevice;->close(ZZ)V\n'
                '\n'
                '    .line 52\n',
                '    invoke-virtual {v0, v3, p0}, Lcom/oplus/ocs/camera/CameraDevice;->close(ZZ)V\n'
                '\n'
                '    const-string p0, "OP15Close"\n'
                '\n'
                '    const-string v0, "f0 returned from CameraDevice.close"\n'
                '\n'
                '    invoke-static {p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 52\n',
                1,
            )

        if smali.match('*/s7/g0.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 15\n',
                '.method public final run()V\n'
                '    .locals 15\n'
                '\n'
                '    const-string v13, "OP15Preview"\n'
                '\n'
                '    const-string v14, "g0 run entry"\n'
                '\n'
                '    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v13\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object v6, v0, Ls7/b1;->o:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 387\n'
                '    .line 388\n'
                '    invoke-virtual {v6}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    .line 389\n',
                '    iget-object v6, v0, Ls7/b1;->o:Landroid/os/ConditionVariable;\n'
                '\n'
                '    const-string v13, "OP15Preview"\n'
                '\n'
                '    const-string v14, "g0 waiting session configured"\n'
                '\n'
                '    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    .line 387\n'
                '    .line 388\n'
                '    invoke-virtual {v6}, Landroid/os/ConditionVariable;->block()V\n'
                '\n'
                '    const-string v13, "OP15Preview"\n'
                '\n'
                '    const-string v14, "g0 session configured released"\n'
                '\n'
                '    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    .line 389\n',
                1,
            )

        if smali.match('*/uj/b.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 13\n',
                '.method public final run()V\n'
                '    .locals 13\n'
                '\n'
                '    const-string v9, "OP15Switch"\n'
                '\n'
                '    const-string v10, "OpenRunnable.run entry"\n'
                '\n'
                '    invoke-static {v9, v10}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v9\n',
                1,
            )
            fixed = fixed.replace(
                '    new-instance v9, Luj/e;\n'
                '\n'
                '    .line 166\n',
                '    const-string v9, "OP15Switch"\n'
                '\n'
                '    new-instance v10, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v11, "OpenRunnable resolved cameraId="\n'
                '\n'
                '    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v11, " openType="\n'
                '\n'
                '    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v10, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v10\n'
                '\n'
                '    invoke-static {v9, v10}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v9\n'
                '\n'
                '    new-instance v9, Luj/e;\n'
                '\n'
                '    .line 166\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-interface {p0, v4, v3}, Ls7/x$c;->s(ILs7/x$d;)V\n'
                '\n'
                '    .line 346\n',
                '    invoke-interface {p0, v4, v3}, Ls7/x$c;->s(ILs7/x$d;)V\n'
                '\n'
                '    const-string p0, "OP15Switch"\n'
                '\n'
                '    const-string v3, "OpenRunnable requested camera open"\n'
                '\n'
                '    invoke-static {p0, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 346\n',
                1,
            )

        if smali.match('*/t5/x0.smali'):
            fixed = _noop_smali_method(fixed, 'public static varargs c([I)V')
            fixed = _noop_smali_method(fixed, 'public static varargs g(Lt5/x0$a;[I)V')

        if smali.match('*/a7/i3.smali'):
            fixed = _noop_smali_method(fixed, 'static constructor <clinit>()V')
            fixed = fixed.replace(
                'Lcom/oplus/shoulderpressure/OplusShoulderPressureManager;',
                'Ljava/lang/Object;',
            )

        if smali.match('*/a7/c3.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static a(Landroid/content/Context;)I',
                '    .locals 1\n'
                '\n'
                '    const/16 v0, 0xff\n'
                '\n'
                '    return v0\n'
            )

        if smali.match('*/a7/e1.smali'):
            fixed = _noop_smali_method(fixed, 'public static e(I)V')

        if smali.match('*/s7/p.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static c(I)Ljava/lang/String;',
                '    .locals 1\n'
                '\n'
                '    packed-switch p0, :pswitch_data_0\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return-object v0\n'
                '\n'
                '    :pswitch_0\n'
                '    const-string v0, "rear_main"\n'
                '\n'
                '    return-object v0\n'
                '\n'
                '    :pswitch_1\n'
                '    const-string v0, "front_main"\n'
                '\n'
                '    return-object v0\n'
                '\n'
                '    :pswitch_2\n'
                '    const-string v0, "rear_wide"\n'
                '\n'
                '    return-object v0\n'
                '\n'
                '    :pswitch_3\n'
                '    const-string v0, "rear_tele"\n'
                '\n'
                '    return-object v0\n'
                '\n'
                '    :pswitch_4\n'
                '    const-string v0, "rear_ultra_tele"\n'
                '\n'
                '    return-object v0\n'
                '\n'
                '    :pswitch_data_0\n'
                '    .packed-switch 0x0\n'
                '        :pswitch_0\n'
                '        :pswitch_1\n'
                '        :pswitch_2\n'
                '        :pswitch_3\n'
                '        :pswitch_4\n'
                '    .end packed-switch\n',
            )

        if smali.match('*/s7/j.smali'):
            fixed = re.sub(
                r'(?ms)^(\s*)invoke-interface \{v0\}, Ljava/util/List;->size\(\)I\n'
                r'\n'
                r'\s*\.line 1062\n'
                r'\s*\.line 1063\n'
                r'\s*\.line 1064\n'
                r'\s*move-result v0\n'
                r'\n'
                r'\s*\.line 1065\n',
                r'\1move v0, v1\n\n    .line 1065\n',
                fixed,
                count=1,
            )

        if smali.match('*/tk/g.smali'):
            fixed = fixed.replace(
                '    :cond_c\n'
                '    :goto_4\n'
                '    iget-boolean p1, p0, Ltk/g;->S0:Z\n'
                '\n'
                '    .line 213\n'
                '    .line 214\n'
                '    if-eqz p1, :cond_f\n'
                '\n'
                '    .line 215\n',
                '    :cond_c\n'
                '    :goto_4\n'
                '    const/4 p1, 0x1\n'
                '\n'
                '    .line 213\n'
                '    .line 214\n'
                '    if-eqz p1, :cond_f\n'
                '\n'
                '    .line 215\n',
                1,
            )

        if smali.match('*/mm/d2.smali') or smali.match('*/mm/h2.smali') or smali.match('*/ai/a.smali'):
            fixed = re.sub(
                r'(?m)^\.implements Landroid/os/OplusKeyEventManager\$OnKeyEventObserver;\n',
                '',
                fixed,
            )

        if smali.match('*/mm/g2.smali'):
            fixed = _noop_smali_method(fixed, 'public final b(Landroid/app/Activity;)V')
            fixed = _noop_smali_method(fixed, 'public final c(Landroid/app/Activity;)V')

        if smali.match('*/mm/i2.smali'):
            fixed = _noop_smali_method(fixed, 'public final b(Landroid/app/Activity;)V')
            fixed = _noop_smali_method(fixed, 'public final c(Landroid/app/Activity;)V')

        if smali.match('*/ai/b.smali'):
            fixed = re.sub(
                r'(?ms)^(\s*)invoke-static \{\}, Landroid/os/OplusKeyEventManager;->getInstance\(\)Landroid/os/OplusKeyEventManager;\n'
                r'.*?^\s*invoke-virtual \{[^}]+\}, Landroid/os/OplusKeyEventManager;->[^\n]+\n'
                r'\s*move-result ([vp]\d+)',
                r'\1const/4 \2, 0x0',
                fixed,
            )
            fixed = re.sub(
                r'(?ms)^(\s*)invoke-static \{\}, Landroid/os/OplusKeyEventManager;->getInstance\(\)Landroid/os/OplusKeyEventManager;\n'
                r'.*?^\s*move-result-object ([vp]\d+)\n'
                r'.*?^\s*invoke-virtual \{[^}]+\}, Landroid/os/OplusKeyEventManager;->[^\n]+\n'
                r'.*?^\s*move-result ([vp]\d+)',
                r'\1const/4 \3, 0x0',
                fixed,
            )

        if smali.match('*/k6/l.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public constructor <init>()V',
                '    .locals 2\n'
                '\n'
                '    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    iput-boolean v0, p0, Lk6/l;->a:Z\n'
                '\n'
                '    iput-boolean v0, p0, Lk6/l;->e:Z\n'
                '\n'
                '    iput-boolean v0, p0, Lk6/l;->f:Z\n'
                '\n'
                '    iput v0, p0, Lk6/l;->i:I\n'
                '\n'
                '    iput-boolean v0, p0, Lk6/l;->j:Z\n'
                '\n'
                '    const-wide/16 v0, 0x0\n'
                '\n'
                '    iput-wide v0, p0, Lk6/l;->k:J\n'
                '\n'
                '    return-void\n'
            )
            fixed = _noop_smali_method(fixed, 'public final a(JZ)V')
            fixed = _noop_smali_method(fixed, 'public final b()V')
            fixed = _noop_smali_method(fixed, 'public final c()V')
            fixed = _noop_smali_method(fixed, 'public final d(I)V')
            fixed = _noop_smali_method(fixed, 'public final e()V')
            fixed = _noop_smali_method(fixed, 'public final f()V')
            fixed = _noop_smali_method(fixed, 'public final g(II)V')

        if smali.match('*/k6/l$a.smali'):
            fixed = _noop_smali_method(fixed, 'public final handleMessage(Landroid/os/Message;)V')

        if smali.match('*/p3/a.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static a(Landroid/content/Context;)Ljava/lang/Object;',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return-object v0\n'
            )
            fixed = _replace_smali_method(
                fixed,
                'public static b(IIII)I',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n'
            )
            fixed = _replace_smali_method(
                fixed,
                'public static c()Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n'
            )
            fixed = _noop_smali_method(fixed, 'public static d(Landroid/content/Context;)V')
            fixed = _noop_smali_method(fixed, 'public static e(Ljava/lang/Object;IIIII)V')

        if smali.match('*/eo/j0.smali'):
            fixed = _noop_smali_method(fixed, 'public final b()V')

        if smali.match('*/eo/j0$a.smali') or smali.match('*/com/oplus/camera/feature/out/screen/capture/MultiDisplayManager$e.smali'):
            fixed = _noop_smali_method(fixed, 'public final onActivityEnter(Ljava/lang/Object;)V')
            fixed = _noop_smali_method(fixed, 'public final onActivityExit(Ljava/lang/Object;)V')
            fixed = _noop_smali_method(fixed, 'public final onAppEnter(Ljava/lang/Object;)V')
            fixed = _noop_smali_method(fixed, 'public final onAppExit(Ljava/lang/Object;)V')

        if smali.match('*/eo/s1.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public final a(Landroid/app/Activity;)Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )
            fixed = _noop_smali_method(fixed, 'public final c(Landroid/app/Activity;Lvj/d;)V')
            fixed = _noop_smali_method(fixed, 'public final d()V')
            fixed = _noop_smali_method(fixed, 'public final e()V')

        if smali.match('*/com/oplus/camera/feature/out/screen/capture/MultiDisplayManager.smali'):
            fixed = _noop_smali_method(fixed, 'public h(Landroid/content/Context;)V')

        if smali.match('*/com/oplus/camera/CameraManager.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static V0()Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )
            fixed = _replace_smali_method(
                fixed,
                'public final m1(Z)V',
                '    .locals 1\n'
                '\n'
                '    iput-boolean p1, p0, Lcom/oplus/camera/CameraManager;->l0:Z\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    iput-boolean v0, p0, Lcom/oplus/camera/CameraManager;->m0:Z\n'
                '\n'
                '    return-void\n',
            )
            fixed = _noop_smali_method(fixed, 'public final F6()V')

        if False and smali.match('*/com/oplus/ocs/camera/CameraDeviceAdapterV2.smali'):
            fixed = fixed.replace(
                '.field private mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n',
                '.field private static sOp15LastPreviewAssistCallback:Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;\n'
                '\n'
                '.field private static sOp15LastPreviewCallback:Lcom/oplus/ocs/camera/CameraPreviewCallback;\n'
                '\n'
                '.field private static sOp15LastPreviewHandler:Landroid/os/Handler;\n'
                '\n'
                '.field private static sOp15LastPreviewSurfaces:Ljava/util/Map;\n'
                '\n'
                '.field private static sOp15LastSdkConfig:Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '.field private mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n',
                1,
            )
            fixed = _replace_smali_method(
                fixed,
                'public constructor <init>(Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;)V',
                '    .locals 0\n'
                '\n'
                '    invoke-direct {p0}, Lcom/oplus/ocs/camera/CameraDeviceAdapter;-><init>()V\n'
                '\n'
                '    iput-object p1, p0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n'
                '\n'
                '    return-void\n',
            )
            fixed = _replace_smali_method(
                fixed,
                'public configure(Lcom/oplus/ocs/camera/CameraDeviceConfig;)V',
                '    .locals 4\n'
                '\n'
                '    iget-object v0, p0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n'
                '\n'
                '    if-eqz v0, :cond_0\n'
                '\n'
                '    invoke-virtual {p1}, Lcom/oplus/ocs/camera/CameraDeviceConfig;->getConfig()Ljava/lang/Object;\n'
                '\n'
                '    move-result-object v0\n'
                '\n'
                '    instance-of v0, v0, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    if-eqz v0, :cond_0\n'
                '\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n'
                '\n'
                '    invoke-virtual {p1}, Lcom/oplus/ocs/camera/CameraDeviceConfig;->getConfig()Ljava/lang/Object;\n'
                '\n'
                '    move-result-object p1\n'
                '\n'
                '    check-cast p1, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    sput-object p1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastSdkConfig:Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    invoke-interface {p0, p1}, Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;->configure(Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;)V\n'
                '\n'
                '    sget-object p1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewSurfaces:Ljava/util/Map;\n'
                '\n'
                '    if-eqz p1, :cond_0\n'
                '\n'
                '    sget-object v0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewCallback:Lcom/oplus/ocs/camera/CameraPreviewCallback;\n'
                '\n'
                '    if-eqz v0, :cond_0\n'
                '\n'
                '    sget-object v1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewHandler:Landroid/os/Handler;\n'
                '\n'
                '    if-eqz v1, :cond_0\n'
                '\n'
                '    const-string v2, "OP15Preview"\n'
                '\n'
                '    const-string v3, "configure replay cached startPreview"\n'
                '\n'
                '    invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v2\n'
                '\n'
                '    new-instance v2, Lcom/oplus/ocs/camera/CameraPreviewCallbackAdapterV2;\n'
                '\n'
                '    invoke-direct {v2, v0}, Lcom/oplus/ocs/camera/CameraPreviewCallbackAdapterV2;-><init>(Lcom/oplus/ocs/camera/CameraPreviewCallback;)V\n'
                '\n'
                '    sget-object v0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewAssistCallback:Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;\n'
                '\n'
                '    new-instance v3, Lcom/oplus/ocs/camera/CameraPreviewAssistCallbackAdapterV2;\n'
                '\n'
                '    invoke-direct {v3, v0}, Lcom/oplus/ocs/camera/CameraPreviewAssistCallbackAdapterV2;-><init>(Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;)V\n'
                '\n'
                '    invoke-interface {p0, p1, v2, v1, v3}, Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;->startPreview(Ljava/util/Map;Lcom/oplus/ocs/camera/appinterface/CameraPreviewCallbackAdapter;Landroid/os/Handler;Lcom/oplus/ocs/camera/appinterface/CameraPreviewAssistCallbackAdapter;)V\n'
                '\n'
                '    :cond_0\n'
                '    return-void\n',
            )
            fixed = _replace_smali_method(
                fixed,
                'public startPreview(Ljava/util/Map;Lcom/oplus/ocs/camera/CameraPreviewCallback;Landroid/os/Handler;Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;)V',
                '    .locals 1\n'
                '    .annotation system Ldalvik/annotation/Signature;\n'
                '        value = {\n'
                '            "(",\n'
                '            "Ljava/util/Map<",\n'
                '            "Ljava/lang/String;",\n'
                '            "Landroid/view/Surface;",\n'
                '            ">;",\n'
                '            "Lcom/oplus/ocs/camera/CameraPreviewCallback;",\n'
                '            "Landroid/os/Handler;",\n'
                '            "Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;",\n'
                '            ")V"\n'
                '        }\n'
                '    .end annotation\n'
                '\n'
                '    sput-object p1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewSurfaces:Ljava/util/Map;\n'
                '\n'
                '    sput-object p2, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewCallback:Lcom/oplus/ocs/camera/CameraPreviewCallback;\n'
                '\n'
                '    sput-object p3, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewHandler:Landroid/os/Handler;\n'
                '\n'
                '    sput-object p4, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewAssistCallback:Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;\n'
                '\n'
                '    const-string v0, "OP15Preview"\n'
                '\n'
                '    const-string p2, "cache startPreview args"\n'
                '\n'
                '    invoke-static {v0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p2\n'
                '\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n'
                '\n'
                '    if-eqz p0, :cond_0\n'
                '\n'
                '    new-instance v0, Lcom/oplus/ocs/camera/CameraPreviewCallbackAdapterV2;\n'
                '\n'
                '    sget-object p2, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewCallback:Lcom/oplus/ocs/camera/CameraPreviewCallback;\n'
                '\n'
                '    invoke-direct {v0, p2}, Lcom/oplus/ocs/camera/CameraPreviewCallbackAdapterV2;-><init>(Lcom/oplus/ocs/camera/CameraPreviewCallback;)V\n'
                '\n'
                '    new-instance p2, Lcom/oplus/ocs/camera/CameraPreviewAssistCallbackAdapterV2;\n'
                '\n'
                '    invoke-direct {p2, p4}, Lcom/oplus/ocs/camera/CameraPreviewAssistCallbackAdapterV2;-><init>(Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;)V\n'
                '\n'
                '    invoke-interface {p0, p1, v0, p3, p2}, Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;->startPreview(Ljava/util/Map;Lcom/oplus/ocs/camera/appinterface/CameraPreviewCallbackAdapter;Landroid/os/Handler;Lcom/oplus/ocs/camera/appinterface/CameraPreviewAssistCallbackAdapter;)V\n'
                '\n'
                '    :cond_0\n'
                '    return-void\n',
            )
            fixed = fixed.replace(
                '\n.method public resumeRecording()V\n',
                '\n.method public op15ReplayCachedPreview()V\n'
                '    .locals 5\n'
                '\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->mCameraDeviceInterface:Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;\n'
                '\n'
                '    if-eqz p0, :cond_0\n'
                '\n'
                '    sget-object v0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastSdkConfig:Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    if-eqz v0, :cond_op15_no_config\n'
                '\n'
                '    const-string v3, "OP15Preview"\n'
                '\n'
                '    const-string v4, "onOpened replay cached configure"\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    invoke-interface {p0, v0}, Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;->configure(Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;)V\n'
                '\n'
                '    :cond_op15_no_config\n'
                '    sget-object v0, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewSurfaces:Ljava/util/Map;\n'
                '\n'
                '    if-eqz v0, :cond_0\n'
                '\n'
                '    sget-object v1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewCallback:Lcom/oplus/ocs/camera/CameraPreviewCallback;\n'
                '\n'
                '    if-eqz v1, :cond_0\n'
                '\n'
                '    sget-object v2, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewHandler:Landroid/os/Handler;\n'
                '\n'
                '    if-eqz v2, :cond_0\n'
                '\n'
                '    const-string v3, "OP15Preview"\n'
                '\n'
                '    const-string v4, "onOpened replay cached startPreview"\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    new-instance v3, Lcom/oplus/ocs/camera/CameraPreviewCallbackAdapterV2;\n'
                '\n'
                '    invoke-direct {v3, v1}, Lcom/oplus/ocs/camera/CameraPreviewCallbackAdapterV2;-><init>(Lcom/oplus/ocs/camera/CameraPreviewCallback;)V\n'
                '\n'
                '    sget-object v1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;->sOp15LastPreviewAssistCallback:Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;\n'
                '\n'
                '    new-instance v4, Lcom/oplus/ocs/camera/CameraPreviewAssistCallbackAdapterV2;\n'
                '\n'
                '    invoke-direct {v4, v1}, Lcom/oplus/ocs/camera/CameraPreviewAssistCallbackAdapterV2;-><init>(Lcom/oplus/ocs/camera/CameraPreviewAssistCallback;)V\n'
                '\n'
                '    invoke-interface {p0, v0, v3, v2, v4}, Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;->startPreview(Ljava/util/Map;Lcom/oplus/ocs/camera/appinterface/CameraPreviewCallbackAdapter;Landroid/os/Handler;Lcom/oplus/ocs/camera/appinterface/CameraPreviewAssistCallbackAdapter;)V\n'
                '\n'
                '    :cond_0\n'
                '    return-void\n'
                '.end method\n'
                '\n.method public resumeRecording()V\n',
                1,
            )

        if False and smali.match('*/com/oplus/ocs/camera/CameraStateCallbackAdapterV2.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public onCameraOpened(Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;)V',
                '    .locals 4\n'
                '\n'
                '    invoke-super {p0, p1}, Lcom/oplus/ocs/camera/appinterface/CameraStateCallbackAdapter;->onCameraOpened(Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;)V\n'
                '\n'
                '    const-string v0, "OP15Unit"\n'
                '\n'
                '    new-instance v1, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v2, "V2 onCameraOpened legacyCallback="\n'
                '\n'
                '    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    iget-object v2, p0, Lcom/oplus/ocs/camera/CameraStateCallbackAdapterV2;->mCameraStateCallback:Lcom/oplus/ocs/camera/CameraStateCallback;\n'
                '\n'
                '    if-eqz v2, :cond_op15_null_callback\n'
                '\n'
                '    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;\n'
                '\n'
                '    move-result-object v3\n'
                '\n'
                '    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v3\n'
                '\n'
                '    goto :goto_op15_log_callback\n'
                '\n'
                '    :cond_op15_null_callback\n'
                '    const-string v3, "null"\n'
                '\n'
                '    :goto_op15_log_callback\n'
                '    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/CameraStateCallbackAdapterV2;->mCameraStateCallback:Lcom/oplus/ocs/camera/CameraStateCallback;\n'
                '\n'
                '    if-eqz p0, :cond_0\n'
                '\n'
                '    new-instance v0, Lcom/oplus/ocs/camera/CameraDevice;\n'
                '\n'
                '    new-instance v1, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;\n'
                '\n'
                '    invoke-direct {v1, p1}, Lcom/oplus/ocs/camera/CameraDeviceAdapterV2;-><init>(Lcom/oplus/ocs/camera/appinterface/CameraDeviceInterface;)V\n'
                '\n'
                '    invoke-direct {v0, v1}, Lcom/oplus/ocs/camera/CameraDevice;-><init>(Lcom/oplus/ocs/camera/CameraDeviceAdapter;)V\n'
                '\n'
                '    invoke-virtual {p0, v0}, Lcom/oplus/ocs/camera/CameraStateCallback;->onCameraOpened(Lcom/oplus/ocs/camera/CameraDevice;)V\n'
                '\n'
                '    :cond_0\n'
                '    return-void\n',
            )

        if smali.match('*/androidx/window/layout/a.smali'):
            fixed = fixed.replace(
                '    :pswitch_c\n'
                '    iget-object v0, p0, Landroidx/window/layout/a;->b:Ljava/lang/Object;\n',
                '    :pswitch_c\n'
                '    const-string v13, "OP15Switch"\n'
                '\n'
                '    const-string v14, "layout/a camera-open runnable entry"\n'
                '\n'
                '    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    iget-object v0, p0, Landroidx/window/layout/a;->b:Ljava/lang/Object;\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object v1, v0, Ls7/c1;->b:Ls7/b1;\n'
                '\n'
                '    .line 1450\n'
                '    .line 1451\n'
                '    iget-object v1, v1, Ls7/b1;->b:Ls7/v;\n'
                '\n'
                '    .line 1452\n'
                '    .line 1453\n'
                '    if-eqz v1, :cond_19\n',
                '    iget-object v1, v0, Ls7/c1;->b:Ls7/b1;\n'
                '\n'
                '    .line 1450\n'
                '    .line 1451\n'
                '    iget-object v1, v1, Ls7/b1;->b:Ls7/v;\n'
                '\n'
                '    .line 1452\n'
                '    .line 1453\n'
                '    if-eqz v1, :cond_op15_layout_null_device\n'
                '\n'
                '    goto :goto_op15_layout_has_device\n'
                '\n'
                '    :cond_op15_layout_null_device\n'
                '    const-string v13, "OP15Switch"\n'
                '\n'
                '    const-string v14, "layout/a skip: b1 camera wrapper is null"\n'
                '\n'
                '    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    goto :cond_19\n'
                '\n'
                '    :goto_op15_layout_has_device\n',
                1,
            )
            fixed = fixed.replace(
                '    iget v0, v0, Ls7/b1;->t:I\n'
                '\n'
                '    .line 1460\n'
                '    .line 1461\n'
                '    invoke-interface {v1, p0, v0}, Ls7/x$d;->f(Lcom/oplus/ocs/camera/CameraDevice;I)V\n',
                '    iget v0, v0, Ls7/b1;->t:I\n'
                '\n'
                '    const-string v13, "OP15Switch"\n'
                '\n'
                '    new-instance v14, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v12, "layout/a dispatch app onCameraOpened cameraId="\n'
                '\n'
                '    invoke-direct {v14, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v14, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v14\n'
                '\n'
                '    invoke-static {v13, v14}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v13\n'
                '\n'
                '    .line 1460\n'
                '    .line 1461\n'
                '    invoke-interface {v1, p0, v0}, Ls7/x$d;->f(Lcom/oplus/ocs/camera/CameraDevice;I)V\n',
                1,
            )

        if smali.match('*/s7/c1.smali'):
            fixed = fixed.replace(
                '.method public final onCameraOpened(Lcom/oplus/ocs/camera/CameraDevice;)V\n'
                '    .locals 4\n',
                '.method public final onCameraOpened(Lcom/oplus/ocs/camera/CameraDevice;)V\n'
                '    .locals 6\n',
                1,
            )
            fixed = fixed.replace(
                '.method public final onCameraClosed()V\n'
                '    .locals 5\n',
                '.method public final onCameraClosed()V\n'
                '    .locals 5\n'
                '\n'
                '    const-string v0, "OP15Close"\n'
                '\n'
                '    const-string v1, "c1.onCameraClosed entry"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p0, v3, Ls7/b1;->p:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 67\n'
                '    .line 68\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    .line 69\n',
                '    iget-object p0, v3, Ls7/b1;->p:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 67\n'
                '    .line 68\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    const-string p0, "OP15Close"\n'
                '\n'
                '    const-string v1, "c1.onCameraClosed opened n/o/p"\n'
                '\n'
                '    invoke-static {p0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 69\n',
                1,
            )
            fixed = fixed.replace(
                '.method public final onSessionConfigured()V\n'
                '    .locals 3\n',
                '.method public final onSessionConfigured()V\n'
                '    .locals 3\n'
                '\n'
                '    const-string v1, "OP15Preview"\n'
                '\n'
                '    const-string v2, "c1 onSessionConfigured opens b1.o"\n'
                '\n'
                '    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v1\n',
                1,
            )
            fixed = fixed.replace(
                '    iput v1, v0, Ls7/b1;->t:I\n'
                '\n'
                '    .line 47\n'
                '    .line 48\n'
                '    new-instance v1, Landroidx/window/embedding/c;\n'
                '\n'
                '    .line 49\n'
                '    .line 50\n'
                '    invoke-direct {v1, v2, p0, p1}, Landroidx/window/embedding/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V\n'
                '\n'
                '    .line 51\n'
                '    .line 52\n'
                '    .line 53\n'
                '    invoke-virtual {v0, v1}, Ls7/b1;->G(Ljava/lang/Runnable;)V\n'
                '\n'
                '    .line 54\n'
                '    .line 55\n'
                '    .line 56\n'
                '    iget-object v1, v0, Ls7/b1;->v:Ls7/b1$a;\n'
                '\n'
                '    .line 57\n'
                '    .line 58\n'
                '    invoke-virtual {v1}, Lx6/c;->d()Landroid/os/Handler;\n'
                '\n'
                '    .line 59\n'
                '    .line 60\n'
                '    .line 61\n'
                '    move-result-object v1\n'
                '\n'
                '    .line 62\n'
                '    new-instance v3, Landroidx/window/layout/a;\n'
                '\n'
                '    .line 63\n'
                '    .line 64\n'
                '    invoke-direct {v3, v2, p0, p1}, Landroidx/window/layout/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V\n'
                '\n'
                '    .line 65\n'
                '    .line 66\n'
                '    .line 67\n'
                '    invoke-virtual {v1, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z\n'
                '\n'
                '    .line 68\n',
                '    iput v1, v0, Ls7/b1;->t:I\n'
                '\n'
                '    .line 47\n'
                '    .line 48\n'
                '    new-instance v1, Landroidx/window/embedding/c;\n'
                '\n'
                '    invoke-direct {v1, v2, p0, p1}, Landroidx/window/embedding/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V\n'
                '\n'
                '    invoke-virtual {v0, v1}, Ls7/b1;->G(Ljava/lang/Runnable;)V\n'
                '\n'
                '    const-string v1, "OP15Switch"\n'
                '\n'
                '    const-string v3, "c1 initialized b1.G before camera-open dispatch"\n'
                '\n'
                '    invoke-static {v1, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v1\n'
                '\n'
                '    iget-object v1, v0, Ls7/b1;->v:Ls7/b1$a;\n'
                '\n'
                '    invoke-virtual {v1}, Lx6/c;->d()Landroid/os/Handler;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    new-instance v3, Landroidx/window/layout/a;\n'
                '\n'
                '    invoke-direct {v3, v2, p0, p1}, Landroidx/window/layout/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V\n'
                '\n'
                '    invoke-virtual {v1, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z\n'
                '\n'
                '    move-result v3\n'
                '\n'
                '    const-string v4, "OP15Switch"\n'
                '\n'
                '    new-instance v5, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string p0, "c1 posted layout/a result="\n'
                '\n'
                '    invoke-direct {v5, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string p0, " handler="\n'
                '\n'
                '    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string p0, " looper="\n'
                '\n'
                '    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    invoke-static {v4, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 68\n',
                1,
            )

        if smali.match('*/s7/c1$a.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 0\n'
                '\n'
                '    .line 1\n'
                '    iget-object p0, p0, Ls7/c1$a;->a:Ls7/c1;\n'
                '\n'
                '    .line 2\n'
                '    .line 3\n'
                '    iget-object p0, p0, Ls7/c1;->b:Ls7/b1;\n'
                '\n'
                '    .line 4\n'
                '    .line 5\n'
                '    iget-object p0, p0, Ls7/b1;->z:Ls7/x$d;\n'
                '\n'
                '    .line 6\n'
                '    .line 7\n'
                '    invoke-interface {p0}, Ls7/x$d;->a()V\n'
                '\n'
                '    .line 8\n'
                '    .line 9\n'
                '    .line 10\n'
                '    return-void\n'
                '.end method',
                '.method public final run()V\n'
                '    .locals 2\n'
                '\n'
                '    const-string v0, "OP15Close"\n'
                '\n'
                '    const-string v1, "c1$a run entry"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    .line 1\n'
                '    iget-object p0, p0, Ls7/c1$a;->a:Ls7/c1;\n'
                '\n'
                '    .line 2\n'
                '    .line 3\n'
                '    iget-object p0, p0, Ls7/c1;->b:Ls7/b1;\n'
                '\n'
                '    .line 4\n'
                '    .line 5\n'
                '    iget-object p0, p0, Ls7/b1;->z:Ls7/x$d;\n'
                '\n'
                '    const-string v0, "OP15Close"\n'
                '\n'
                '    const-string v1, "c1$a before z.a"\n'
                '\n'
                '    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v0\n'
                '\n'
                '    .line 6\n'
                '    .line 7\n'
                '    invoke-interface {p0}, Ls7/x$d;->a()V\n'
                '\n'
                '    const-string p0, "OP15Close"\n'
                '\n'
                '    const-string v0, "c1$a after z.a"\n'
                '\n'
                '    invoke-static {p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    .line 8\n'
                '    .line 9\n'
                '    .line 10\n'
                '    return-void\n'
                '.end method',
                1,
            )

        if smali.match('*/x6/z.smali'):
            fixed = fixed.replace(
                '.method public final a(Ljava/lang/String;Ljava/lang/Runnable;)V\n'
                '    .locals 1\n',
                '.method public final a(Ljava/lang/String;Ljava/lang/Runnable;)V\n'
                '    .locals 4\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;\n',
                '    const-string v1, "OP15TaskBus"\n'
                '\n'
                '    new-instance v2, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v3, "schedule task="\n'
                '\n'
                '    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v2\n'
                '\n'
                '    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v1\n'
                '\n'
                '    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p0, p0, Lx6/z;->a:Lx6/z$a;\n'
                '\n'
                '    .line 10\n'
                '    .line 11\n'
                '    invoke-virtual {p0, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V\n',
                '    iget-object p0, p0, Lx6/z;->a:Lx6/z$a;\n'
                '\n'
                '    .line 10\n'
                '    .line 11\n'
                '    invoke-virtual {p0, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V\n'
                '\n'
                '    const-string p0, "OP15TaskBus"\n'
                '\n'
                '    const-string p1, "execute accepted"\n'
                '\n'
                '    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n',
                1,
            )

        if smali.match('*/x6/z$d.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 3\n',
                '.method public final run()V\n'
                '    .locals 5\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object v0, p0, Lx6/z$d;->b:Ljava/lang/String;\n',
                '    iget-object v0, p0, Lx6/z$d;->b:Ljava/lang/String;\n'
                '\n'
                '    const-string v3, "OP15TaskBus"\n'
                '\n'
                '    new-instance v4, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v1, "run start task="\n'
                '\n'
                '    invoke-direct {v4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v4\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n',
                1,
            )
            fixed = fixed.replace(
                '    invoke-interface {v1}, Ljava/lang/Runnable;->run()V\n',
                '    invoke-interface {v1}, Ljava/lang/Runnable;->run()V\n'
                '\n'
                '    const-string v3, "OP15TaskBus"\n'
                '\n'
                '    new-instance v4, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v1, "run end task="\n'
                '\n'
                '    invoke-direct {v4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v4\n'
                '\n'
                '    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v3\n',
                1,
            )

        if smali.match('*/vj/i.smali'):
            fixed = fixed.replace(
                '.method public final run()V\n'
                '    .locals 10\n',
                '.method public final run()V\n'
                '    .locals 13\n'
                '\n'
                '    const-string v10, "OP15Preview"\n'
                '\n'
                '    const-string v11, "vj/i run entry"\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n',
                1,
            )
            fixed = fixed.replace(
                '    iget-object p0, v0, Lvj/k;->L:Landroid/os/ConditionVariable;\n'
                '\n'
                '    .line 370\n'
                '    .line 371\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->open()V\n',
                '    iget-object p0, v0, Lvj/k;->L:Landroid/os/ConditionVariable;\n'
                '\n'
                '    const-string v10, "OP15Preview"\n'
                '\n'
                '    new-instance v11, Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v12, "vj/i opening k="\n'
                '\n'
                '    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V\n'
                '\n'
                '    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I\n'
                '\n'
                '    move-result v12\n'
                '\n'
                '    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    const-string v12, " L="\n'
                '\n'
                '    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I\n'
                '\n'
                '    move-result v12\n'
                '\n'
                '    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;\n'
                '\n'
                '    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
                '\n'
                '    move-result-object v11\n'
                '\n'
                '    invoke-static {v10, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result v10\n'
                '\n'
                '    .line 370\n'
                '    .line 371\n'
                '    invoke-virtual {p0}, Landroid/os/ConditionVariable;->open()V\n'
                '\n'
                '    const-string p0, "OP15Preview"\n'
                '\n'
                '    const-string v10, "vj/i opened L condition"\n'
                '\n'
                '    invoke-static {p0, v10}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n',
                1,
            )

        if smali.match('*/com/oplus/ocs/camera/producer/mode/BaseMode.smali'):
            fixed = fixed.replace(
                '    check-cast p2, Lcom/oplus/ocs/camera/common/util/ApsRequestTag;\n'
                '\n'
                '    iput-object p2, v2, Lcom/oplus/ocs/camera/common/util/CameraRequestTag;->mApsRequestTag:Lcom/oplus/ocs/camera/common/util/ApsRequestTag;\n',
                '    check-cast p2, Lcom/oplus/ocs/camera/common/util/ApsRequestTag;\n'
                '\n'
                '    if-nez p2, :cond_op15_aps_tag_ready\n'
                '\n'
                '    new-instance p2, Lcom/oplus/ocs/camera/common/util/ApsRequestTag;\n'
                '\n'
                '    invoke-direct {p2}, Lcom/oplus/ocs/camera/common/util/ApsRequestTag;-><init>()V\n'
                '\n'
                '    iget-object v6, p0, Lcom/oplus/ocs/camera/producer/mode/BaseMode;->mTagMap:Ljava/util/Map;\n'
                '\n'
                '    invoke-interface {v6, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;\n'
                '\n'
                '    move-result-object v6\n'
                '\n'
                '    :cond_op15_aps_tag_ready\n'
                '    iput-object p2, v2, Lcom/oplus/ocs/camera/common/util/CameraRequestTag;->mApsRequestTag:Lcom/oplus/ocs/camera/common/util/ApsRequestTag;\n',
                1,
            )
            fixed = fixed.replace(
                '    check-cast p2, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    .line 1725\n'
                '    invoke-virtual {p2}, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;->getPictureSurfaces()Ljava/util/List;\n',
                '    check-cast p2, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    if-eqz p2, :cond_60\n'
                '\n'
                '    .line 1725\n'
                '    invoke-virtual {p2}, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;->getPictureSurfaces()Ljava/util/List;\n',
                1,
            )
            fixed = _replace_smali_method(
                fixed,
                'final getConfigureParameter(Ljava/lang/String;)Lcom/oplus/ocs/camera/metadata/parameter/Parameter;',
                '    .locals 2\n'
                '\n'
                '    iget-object p0, p0, Lcom/oplus/ocs/camera/producer/mode/BaseMode;->mConfigMap:Ljava/util/concurrent/ConcurrentHashMap;\n'
                '\n'
                '    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    check-cast p0, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;\n'
                '\n'
                '    if-eqz p0, :cond_0\n'
                '\n'
                '    invoke-virtual {p0}, Lcom/oplus/ocs/camera/common/parameter/SdkCameraDeviceConfig;->getConfigureParameter()Lcom/oplus/ocs/camera/metadata/parameter/Parameter;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    return-object p0\n'
                '\n'
                '    :cond_0\n'
                '    const-string p0, "OP15Preview"\n'
                '\n'
                '    const-string p1, "missing config, using empty configure parameter"\n'
                '\n'
                '    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I\n'
                '\n'
                '    move-result p0\n'
                '\n'
                '    new-instance p0, Lcom/oplus/ocs/camera/metadata/parameter/ConfigureParameter$Builder;\n'
                '\n'
                '    invoke-direct {p0}, Lcom/oplus/ocs/camera/metadata/parameter/ConfigureParameter$Builder;-><init>()V\n'
                '\n'
                '    invoke-virtual {p0}, Lcom/oplus/ocs/camera/metadata/parameter/ConfigureParameter$Builder;->build()Lcom/oplus/ocs/camera/metadata/parameter/Parameter;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    return-object p0\n',
            )

        if smali.match('*/a7/l0.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static m(Ljava/lang/String;)Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )

        if smali.match('*/a7/u3.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static a(Landroid/content/Context;)Landroid/graphics/Typeface;',
                '    .locals 1\n'
                '\n'
                '    sget-object v0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;\n'
                '\n'
                '    return-object v0\n',
            )

        if smali.match('*/j3/a.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static c(Landroid/content/res/Configuration;)Loplus/content/res/OplusExtraConfiguration;',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return-object v0\n',
            )

        fixed = re.sub(
            r'(?m)^(\s*)invoke-static \{[^}]+\}, Landroid/os/OplusManager;->onStamp\(Ljava/lang/String;Ljava/util/Map;\)V',
            r'\1nop',
            fixed,
        )

        if smali.match('*/pm/l1.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public final b()Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )

        if smali.match('*/l9/a.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static g(Landroid/bluetooth/BluetoothDevice;)Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )
            fixed = _replace_smali_method(
                fixed,
                'public static i(Landroid/bluetooth/BluetoothDevice;)Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )

        if smali.match('*/eo/a.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static b(I)I',
                '    .locals 1\n'
                '\n'
                '    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    invoke-virtual {p0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;\n'
                '\n'
                '    move-result-object p0\n'
                '\n'
                '    iget v0, p0, Landroid/util/DisplayMetrics;->densityDpi:I\n'
                '\n'
                '    return v0\n',
            )

        if smali.match('*/com/oplus/camera/util/LayoutUtil.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public static x(Landroid/content/Context;)Z',
                '    .locals 1\n'
                '\n'
                '    const/4 v0, 0x0\n'
                '\n'
                '    return v0\n',
            )

        if smali.match('*/n3/h.smali'):
            fixed = _noop_smali_method(fixed, 'public static e(Landroid/view/View;IIIIII)V')

        if smali.match('*/com/coui/appcompat/dialog/widget/COUIAlertDialogMaxLinearLayout.smali'):
            fixed = _noop_smali_method(fixed, 'private setOutLineProviderInternal(Landroid/graphics/Outline;)V')

        if smali.match('*/com/coui/appcompat/button/COUIButton$a.smali'):
            fixed = _noop_smali_method(fixed, 'public final getOutline(Landroid/view/View;Landroid/graphics/Outline;)V')

        if smali.match('*/com/coui/appcompat/tooltips/COUIToolTips$g.smali'):
            fixed = _noop_smali_method(fixed, 'public final getOutline(Landroid/view/View;Landroid/graphics/Outline;)V')

        if smali.match('*/v7/d.smali'):
            fixed = _noop_smali_method(fixed, 'public final d(Lcom/oplus/camera/MyApplication;)V')
            fixed = _noop_smali_method(fixed, 'public final g()V')

        if smali.match('*/hk/d.smali'):
            fixed = _replace_smali_method(
                fixed,
                'public constructor <init>()V',
                '    .locals 3\n'
                '\n'
                '    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n'
                '\n'
                '    const/4 v0, 0x1\n'
                '\n'
                '    invoke-static {v0}, Ljava/util/concurrent/Executors;->newScheduledThreadPool(I)Ljava/util/concurrent/ScheduledExecutorService;\n'
                '\n'
                '    move-result-object v1\n'
                '\n'
                '    iput-object v1, p0, Lhk/d;->a:Ljava/util/concurrent/ScheduledExecutorService;\n'
                '\n'
                '    const/4 v1, 0x0\n'
                '\n'
                '    iput-object v1, p0, Lhk/d;->b:Ljava/lang/Object;\n'
                '\n'
                '    new-instance v1, Ljava/util/concurrent/atomic/AtomicInteger;\n'
                '\n'
                '    const/4 v2, 0x0\n'
                '\n'
                '    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V\n'
                '\n'
                '    iput-object v1, p0, Lhk/d;->d:Ljava/util/concurrent/atomic/AtomicInteger;\n'
                '\n'
                '    iput-boolean v0, p0, Lhk/d;->e:Z\n'
                '\n'
                '    iput-boolean v2, p0, Lhk/d;->f:Z\n'
                '\n'
                '    new-instance v0, Ljava/lang/Object;\n'
                '\n'
                '    invoke-direct {v0}, Ljava/lang/Object;-><init>()V\n'
                '\n'
                '    iput-object v0, p0, Lhk/d;->h:Ljava/lang/Object;\n'
                '\n'
                '    const/4 v0, -0x1\n'
                '\n'
                '    iput v0, p0, Lhk/d;->i:I\n'
                '\n'
                '    return-void\n',
            )
            fixed = re.sub(
                r'(?m)^(\s*)invoke-virtual \{[^}]+\}, Lcom/oplus/osense/OsenseResEventClient;->requestSceneAction\(Landroid/os/Bundle;\)V',
                r'\1nop',
                fixed,
            )
            fixed = fixed.replace(
                'Lcom/oplus/osense/OsenseResEventClient;',
                'Ljava/lang/Object;',
            )

        if fixed != data:
            smali.write_text(fixed, encoding='utf-8')


def blob_fixup_opluscamera_defer_job_count(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = next(Path(tmp_dir).glob('smali*/ac/o0.smali'), None)
    if smali is None:
        return

    data = smali.read_text(encoding='utf-8')
    fixed = _replace_smali_method(
        data,
        'public final P()I',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, 0x0\n'
        '\n'
        '    return v0\n',
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_camera_unit_op15_camera_type(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    smali = next(
        Path(tmp_dir).glob('smali*/com/oplus/ocs/camera/producer/info/CameraCharacteristicsWrapper.smali'),
        None,
    )
    if smali is None:
        return

    data = smali.read_text(encoding='utf-8')
    fixed = data.replace(
        '    const-class v2, [I\n'
        '\n'
        '    invoke-direct {v0, v1, v2}, Landroid/hardware/camera2/CameraCharacteristics$Key;-><init>(Ljava/lang/String;Ljava/lang/Class;)V\n'
        '\n'
        '    sput-object v0, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsWrapper;->KEY_CUSTOM_CAMERA_TYPE:Landroid/hardware/camera2/CameraCharacteristics$Key;\n',
        '    const-class v2, [I\n'
        '\n'
        '    const-class v3, [B\n'
        '\n'
        '    invoke-direct {v0, v1, v3}, Landroid/hardware/camera2/CameraCharacteristics$Key;-><init>(Ljava/lang/String;Ljava/lang/Class;)V\n'
        '\n'
        '    sput-object v0, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsWrapper;->KEY_CUSTOM_CAMERA_TYPE:Landroid/hardware/camera2/CameraCharacteristics$Key;\n',
        1,
    )
    fixed = fixed.replace(
        '    invoke-virtual {v1, p1}, Landroid/hardware/camera2/CameraCharacteristics;->get(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;\n'
        '\n'
        '    move-result-object v0\n'
        '    :try_end_0\n',
        '    invoke-virtual {v1, p1}, Landroid/hardware/camera2/CameraCharacteristics;->get(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;\n'
        '\n'
        '    move-result-object v0\n'
        '\n'
        '    sget-object v1, Lcom/oplus/ocs/camera/producer/info/CameraCharacteristicsWrapper;->KEY_CUSTOM_CAMERA_TYPE:Landroid/hardware/camera2/CameraCharacteristics$Key;\n'
        '\n'
        '    if-ne p1, v1, :cond_op15_camera_type_done\n'
        '\n'
        '    instance-of v1, v0, [B\n'
        '\n'
        '    if-eqz v1, :cond_op15_camera_type_done\n'
        '\n'
        '    check-cast v0, [B\n'
        '\n'
        '    array-length v1, v0\n'
        '\n'
        '    new-array v1, v1, [I\n'
        '\n'
        '    const/4 v2, 0x0\n'
        '\n'
        '    :goto_op15_camera_type_loop\n'
        '    array-length v3, v0\n'
        '\n'
        '    if-ge v2, v3, :cond_op15_camera_type_converted\n'
        '\n'
        '    aget-byte v3, v0, v2\n'
        '\n'
        '    and-int/lit16 v3, v3, 0xff\n'
        '\n'
        '    aput v3, v1, v2\n'
        '\n'
        '    add-int/lit8 v2, v2, 0x1\n'
        '\n'
        '    goto :goto_op15_camera_type_loop\n'
        '\n'
        '    :cond_op15_camera_type_converted\n'
        '    move-object v0, v1\n'
        '\n'
        '    :cond_op15_camera_type_done\n'
        '    :try_end_0\n',
        1,
    )
    fixed = fixed.replace(
        '    move-result-object p0\n'
        '\n'
        '    check-cast p0, [I\n'
        '\n'
        '    if-eqz p0, :cond_0\n',
        '    move-result-object p0\n'
        '\n'
        '    if-eqz p0, :cond_0\n',
        1,
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_camera_unit_sdk_runtime(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    replacements = {
        'com/google/oplus/protobuf/ExtensionRegistryLite.smali': (
            ('.field private static volatile eagerlyParseMessageSets:Z = false',
             '.field private static volatile eagerlyParseMessageSets:Z'),
        ),
        'com/oplus/camera/hdrtransform/HdrTransformPlatform.smali': (
            ('.field private static sAlgoExists:Z = false',
             '.field private static sAlgoExists:Z'),
            ('.field private static sLibraryLoaded:Z = false',
             '.field private static sLibraryLoaded:Z'),
        ),
        'com/oplus/ocs/camera/UxThreadPool.smali': (
            ('.field private static sThreadUxMap:Landroid/util/SparseArray; = null',
             '.field private static sThreadUxMap:Landroid/util/SparseArray;'),
            ('.field private static sbHasSetUx:Z = false',
             '.field private static sbHasSetUx:Z'),
        ),
        'com/oplus/ocs/camera/common/parameter/apsadapter/ApsHelper.smali': (
            ('.field private static bInit:Z = false',
             '.field private static bInit:Z'),
        ),
        'com/oplus/ocs/camera/common/util/OsenseKeyThreadHelper.smali': (
            ('.field private static sOsenseInit:Z = false',
             '.field private static sOsenseInit:Z'),
        ),
        'com/oplus/ocs/camera/consumer/ApsDataConvert.smali': (
            ('.field private static sbUnderWaterVideoStatus:Z = false',
             '.field private static sbUnderWaterVideoStatus:Z'),
        ),
        'com/oplus/ocs/camera/consumer/apsAdapter/ALog.smali': (
            ('.field private static volatile sEnable:Z = false',
             '.field private static volatile sEnable:Z'),
            ('.field private static volatile sJNILoadFailed:Z = false',
             '.field private static volatile sJNILoadFailed:Z'),
            ('.field private static volatile sLogEncryptEnable:Z = false',
             '.field private static volatile sLogEncryptEnable:Z'),
        ),
        'com/oplus/statistics/util/LogUtil.smali': (
            ('.field private static isDebug:Z = false',
             '.field private static isDebug:Z'),
        ),
    }

    for relative, pairs in replacements.items():
        smali = next(Path(tmp_dir).glob(f'smali*/{relative}'), None)
        if smali is None:
            continue
        data = smali.read_text(encoding='utf-8')
        fixed = data
        for old, new in pairs:
            fixed = fixed.replace(old, new, 1)
        if fixed != data:
            smali.write_text(fixed, encoding='utf-8')

    smali = next(Path(tmp_dir).glob('smali*/com/oplus/ocs/camera/producer/mode/BaseMode.smali'), None)
    if smali is None:
        return

    data = smali.read_text(encoding='utf-8')
    fixed = _replace_smali_method(
        data,
        'public isSensorModeNeedWait(II)Z',
        '    .locals 1\n'
        '\n'
        '    const/4 v0, 0x0\n'
        '\n'
        '    return v0\n',
    )
    sat_identity_pattern = re.compile(
        r'(    invoke-static \{\}, Lcom/oplus/ocs/camera/common/util/Util;->isSystemCamera\(\)Z\n'
        r'\n'
        r'    move-result p2\n'
        r'\n)'
        r'    if-nez p2, (:cond_[0-9a-f]+)\n'
        r'\n'
        r'(    invoke-virtual \{p0, p3\}, Lcom/oplus/ocs/camera/producer/mode/BaseMode;->useOplusCameraCase\(Ljava/lang/String;\)Z\n'
        r'\n'
        r'    move-result p2\n'
        r'\n'
        r'    if-eqz p2, \2\n'
        r'\n'
        r'(?:    \.line \d+\n)?'
        r'    sget-object p2, Lcom/oplus/ocs/camera/metadata/UConfigureKeys;->IS_OPLUS_PACKAGE:Lcom/oplus/ocs/camera/metadata/RequestKey;\n)'
    )
    fixed, sat_count = sat_identity_pattern.subn(r'\1    nop\n\n\3', fixed, count=1)
    if sat_count != 1 and 'UConfigureKeys;->IS_OPLUS_PACKAGE' in fixed and 'useOplusCameraCase(Ljava/lang/String;)Z' in fixed:
        raise ValueError('com.oplus.camera.unit.sdk.jar BaseMode SAT identity guard pattern not found exactly once')
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_camera_unit_facebeauty_probe_path(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Re-point the guarded ProductJni probe from /product/lib64 to /system_ext/lib64.
    if tmp_dir is None:
        return

    old = '/product/lib64/libApsFaceBeautyPreviewProductJni.so'
    new = '/system_ext/lib64/libApsFaceBeautyPreviewProductJni.so'
    smali = _smali_class_file(tmp_dir, 'Lcom/oplus/camera/facebeauty/OplusFaceBeautyPreview;')
    data = smali.read_text(encoding='utf-8', errors='ignore') if smali else ''
    if f'"{old}"' in data:
        smali.write_text(data.replace(old, new), encoding='utf-8')
    elif f'"{new}"' not in data:
        raise ValueError('com.oplus.camera.unit.sdk.jar FaceBeauty ProductJni probe path not found')


def blob_fixup_nativewinbuff_android17(ctx, file, file_path, *args, **kwargs):
    # OOS 16.0.8 calls IGraphicBufferConsumer::releaseBuffer(slot, frame,
    # EGLDisplay, EGLSyncKHR, fence). Android 17's BQ_GL_FENCE_CLEANUP
    # removes the EGL arguments: fence must be in x3, not x5. Both virtual
    # calls currently pass x3 = NULL, crashing libgui in releaseBuffer.
    # Retain the real Fence object and change only its argument register.
    stock_sha256 = '2d725afda39dd9d53bd890e3b22937e05923744cf061b6edd71197bd1e7479f0'
    patched_sha256 = '4420fc766926b54efb79d3cda8db0436ccc873c6af6823052e654fb390bd58fe'
    path = Path(file_path)
    blob = path.read_bytes()
    actual_sha256 = sha256(blob).hexdigest()
    if actual_sha256 == patched_sha256:
        return
    if actual_sha256 != stock_sha256:
        raise ValueError(f'NativeWinBuffExchange stock SHA-256 mismatch: {actual_sha256}')

    patched = bytearray(blob)
    for offset in (0x46D8, 0x4858):
        # mov x3, xzr -> mov x3, sp; sp holds the existing sp<Fence>.
        expected = bytes.fromhex('e3 03 1f aa')
        replacement = bytes.fromhex('e3 03 00 91')
        if blob[offset:offset + 4] != expected:
            raise ValueError(f'NativeWinBuffExchange instruction mismatch at {offset:#x}')
        patched[offset:offset + 4] = replacement

    result = bytes(patched)
    if sha256(result).hexdigest() != patched_sha256:
        raise ValueError('NativeWinBuffExchange patched SHA-256 mismatch')
    path.write_bytes(result)


def blob_fixup_apsclient_force_java_heif(ctx, file, file_path, *args, **kwargs):
    # OPlus supports two HEIF handoffs: optional native helpers when dlopen can
    # resolve them, otherwise its Java-reflection fallback. Stock keeps this APS
    # client in /product and the helpers in /system_ext, so product namespace
    # isolation selects reflection. Our system_ext remap co-located them and
    # unintentionally enabled the native route that stock CPH2747 does not use.
    path = Path(file_path)
    blob = path.read_bytes()
    actual_sha256 = sha256(blob).hexdigest()
    if actual_sha256 != APSCLIENT_STOCK_SHA256:
        raise ValueError(
            'APS client SHA-256 mismatch: '
            f'expected {APSCLIENT_STOCK_SHA256}, found {actual_sha256}'
        )

    patched = bytearray(blob)
    for offset, expected, replacement in APSCLIENT_HEIF_DLOPEN_TARGETS:
        end = offset + len(expected)
        if blob[offset:end] != expected:
            raise ValueError(
                f'APS client dlopen target mismatch at {offset:#x}: '
                f'expected {expected!r}, found {blob[offset:end]!r}'
            )
        patched[offset:end] = replacement

    result = bytes(patched)
    patched_sha256 = sha256(result).hexdigest()
    if patched_sha256 != APSCLIENT_PATCHED_SHA256:
        raise ValueError(
            'patched APS client SHA-256 mismatch: '
            f'expected {APSCLIENT_PATCHED_SHA256}, found {patched_sha256}'
        )
    path.write_bytes(result)


lib_fixups: lib_fixups_user_type = {
    # **lib_fixups already includes the clang RT ubsan and proto 3.9.1
    # fixups that were previously handled by the bash helper functions
    # lib_to_package_fixup_clang_rt_ubsan_standalone and
    # lib_to_package_fixup_proto_3_9_1 — no need to add them explicitly.
    **lib_fixups,
    (
        'libSuperTextWrapper',
        'libXDocProcessSDK',
        'libYTCommon',
        'libmpbase',
        'libextendfile',
    ): lib_fixup_system_ext_suffix,
}

# FileManager smali helpers. Obfuscated class/method/field names change between
# OxygenOS releases, so the fixups below locate their targets through log
# strings, Kotlin debug metadata and framework calls, and only fall back to
# un-obfuscated class names (kept by the app's R8 rules) where those are stable.
_FM_LOG_D = 'Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I'
_FM_METHOD_RE = re.compile(r'(?ms)^\.method (?P<sig>[^\n]+)\n(?P<body>.*?)^\.end method$')


def _fm_find_smali(tmp_dir, needle: str) -> list:
    needle_b = needle.encode('utf-8')
    return [
        path
        for root in sorted(Path(tmp_dir).glob('smali*'))
        if root.is_dir()
        for path in sorted(root.rglob('*.smali'))
        if needle_b in path.read_bytes()
    ]


def _fm_find_class(tmp_dir, rel: str) -> Path:
    for root in sorted(Path(tmp_dir).glob('smali*')):
        if (root / rel).is_file():
            return root / rel
    raise ValueError(f'FileManager: class {rel} not found')


def _fm_only(items: list, what: str):
    if len(items) != 1:
        raise ValueError(f'FileManager: expected exactly one {what}, found {len(items)}')
    return items[0]


def _fm_class_desc(data: str) -> str:
    return re.search(r'(?m)^\.class [^\n]*?(L[^;\s]+;)$', data).group(1)


def _fm_method_name(sig: str) -> str:
    return re.search(r'([\w$<>]+)\(', sig).group(1)


def _fm_method_desc(sig: str) -> str:
    return sig.split()[-1]


def _fm_scene_action(tmp_dir):
    # PerformanceManager.setSceneAction(action: String, timeout: Int) logs
    # "setSceneAction return, isAosp" (stock) / "..., patched" (fixed up).
    anchor = '"setSceneAction return, '
    path = _fm_only(_fm_find_smali(tmp_dir, anchor), 'PerformanceManager class (setSceneAction log)')
    data = path.read_text(encoding='utf-8')
    cls = _fm_class_desc(data)
    method = _fm_only(
        [
            m for m in _FM_METHOD_RE.finditer(data)
            if ' static ' in f' {m["sig"]} '
            and m['sig'].endswith('(Ljava/lang/String;I)V')
            and anchor in m['body']
        ],
        'PerformanceManager.setSceneAction(String, int)',
    )
    call = f'{cls}->{_fm_method_desc(method["sig"])}'
    # Kotlin default-argument wrapper(s) forwarding to setSceneAction.
    calls = [call] + [
        f'{cls}->{_fm_method_desc(m["sig"])}'
        for m in _FM_METHOD_RE.finditer(data)
        if ' synthetic ' in f' {m["sig"]} ' and call in m['body']
    ]
    return path, data, method, calls


def blob_fixup_filemanager_cut_skip_k0_when_same_disk(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return
    # FileActionCut.workRun() calls checkMoveBetweenDevices() (K0() in 16.0.8/
    # 16.0.10) to decide whether a cross-device move dialog is needed, but on
    # LineageOS it crashes silently (swallowed by the thread pool) before
    # logging anything. exceptionDetection() (V()) already stores
    # FileCutHelper.isDirectoriesSameDisk() in a boolean field (V:Z in 16.0.8,
    # Y:Z in 16.0.10), so skip the check for same-disk moves — no cross-device
    # dialog is needed there.
    smali = _fm_find_class(tmp_dir, 'com/filemanager/fileoperate/cut/FileActionCut.smali')
    data = smali.read_text(encoding='utf-8')
    cut = _fm_class_desc(data)

    def helper_call(log_anchor: str, what: str) -> str:
        helper = _fm_only(_fm_find_smali(tmp_dir, log_anchor), f'FileCutHelper class ({what})')
        helper_data = helper.read_text(encoding='utf-8')
        method = _fm_only(
            [
                m for m in _FM_METHOD_RE.finditer(helper_data)
                if m['sig'].endswith('(Ljava/util/List;Ljava/lang/String;)Z') and log_anchor in m['body']
            ],
            f'FileCutHelper.{what}(List, String)',
        )
        return f'{_fm_class_desc(helper_data)}->{_fm_method_desc(method["sig"])}'

    same_disk_call = helper_call('"isDirectoriesSameDisk volumeList "', 'isDirectoriesSameDisk')
    between_devices_call = helper_call('"checkMoveBetweenDevices target:"', 'checkMoveBetweenDevices')

    same_disk_fields = set()
    for m in _FM_METHOD_RE.finditer(data):
        idx = m['body'].find(same_disk_call)
        if idx != -1:
            field = re.search(
                rf'iput-boolean v\d+, p0, {re.escape(cut)}->(\w+):Z', m['body'][idx:]
            )
            if field:
                same_disk_fields.add(field.group(1))
    same_disk = _fm_only(sorted(same_disk_fields), 'FileActionCut same-disk boolean field')

    check = _fm_only(
        [
            _fm_method_name(m['sig']) for m in _FM_METHOD_RE.finditer(data)
            if m['sig'].endswith('()Z') and between_devices_call in m['body']
        ],
        'FileActionCut checkMoveBetweenDevices() wrapper',
    )
    check_call = rf'    invoke-virtual \{{p0\}}, {re.escape(cut)}->{re.escape(check)}\(\)Z\n'

    if re.search(
        rf'    iget-boolean (v\d+), p0, {re.escape(cut)}->{same_disk}:Z\n'
        rf'    if-nez \1, :\w+\n'
        + check_call,
        data,
    ):
        return
    pattern = (
        rf'(?P<call>{check_call}'
        r'\n'
        r'    move-result (?P<reg>v\d+)\n'
        r'\n'
        r'    if-eqz (?P=reg), :(?P<after>\w+)\n)'
    )

    def skip_same_disk(match: re.Match) -> str:
        reg = match.group('reg')
        return (
            f'    iget-boolean {reg}, p0, {cut}->{same_disk}:Z\n'
            f'    if-nez {reg}, :{match.group("after")}\n'
            + match.group('call')
        )

    data, count = re.subn(pattern, skip_same_disk, data)
    if count != 1:
        raise ValueError(
            f'FileManager FileActionCut {check}() call site found {count} times, expected 1'
        )
    smali.write_text(data, encoding='utf-8')


def blob_fixup_filemanager_select_dir_current_path_fallback(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return
    smali = _fm_find_class(tmp_dir, 'com/oplus/selectdir/SelectDirPathPanelFragment.smali')
    data = smali.read_text(encoding='utf-8')
    log_anchor = '    const-string v4, "selectButton click -> select path:"\n'
    button_anchor = '    iget-object p1, p0, Lcom/oplus/selectdir/SelectDirPathPanelFragment;->mSelectButton:Lcom/coui/appcompat/button/COUIButton;\n'
    # The view model's selected-path fallback (B0().getValue()) returns null
    # because it is never populated in this flow. mPathBar.getCurrentPath() is
    # updated on every navigation and is reliable. v1 holds the selectPaths
    # Ref.ObjectRef; v0/p1 are dead at the button anchor.
    new = (
        '    iget-object v0, p0, Lcom/oplus/selectdir/SelectDirPathPanelFragment;->mPathBar:Lcom/filemanager/common/view/BrowserPathBar;\n'
        '    if-eqz v0, :cond_pathbar_skip\n'
        '    invoke-virtual {v0}, Lcom/filemanager/common/view/BrowserPathBar;->getCurrentPath()Ljava/lang/String;\n'
        '    move-result-object v0\n'
        '    if-eqz v0, :cond_pathbar_skip\n'
        '    iget-object p1, v1, Lkotlin/jvm/internal/Ref$ObjectRef;->element:Ljava/lang/Object;\n'
        '    check-cast p1, Ljava/util/List;\n'
        '    if-eqz p1, :cond_pathbar_set\n'
        '    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z\n'
        '    move-result p1\n'
        '    if-eqz p1, :cond_pathbar_skip\n'
        '    :cond_pathbar_set\n'
        '    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;\n'
        '    move-result-object v0\n'
        '    iput-object v0, v1, Lkotlin/jvm/internal/Ref$ObjectRef;->element:Ljava/lang/Object;\n'
        '    :cond_pathbar_skip\n'
    )
    log_idx = data.find(log_anchor)
    button_idx = data.find(button_anchor, log_idx) if log_idx != -1 else -1
    if log_idx == -1 or button_idx == -1 or '.end method' in data[log_idx:button_idx]:
        raise ValueError('FileManager SelectDirPathPanelFragment select button click anchors not found')
    method_start = data.rfind('\n.method ', 0, log_idx)
    if 'new-instance v1, Lkotlin/jvm/internal/Ref$ObjectRef;' not in data[method_start:log_idx]:
        raise ValueError('FileManager SelectDirPathPanelFragment selectPaths Ref.ObjectRef (v1) not found')

    if ':cond_pathbar_skip' in data[log_idx:button_idx]:
        return
    data = data[:button_idx] + new + data[button_idx:]
    smali.write_text(data, encoding='utf-8')


def blob_fixup_filemanager_copycut_skip_osense_scene(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return
    # FileActionBaseCopyCut requests the COPY_CUT osense/orms scene action
    # (c0() in 16.0.8/16.0.10) before copying; the OEM performance service is
    # absent on LineageOS. Stub the method that calls setSceneAction.
    _, _, _, scene_calls = _fm_scene_action(tmp_dir)
    smali = _fm_find_class(tmp_dir, 'com/filemanager/fileoperate/copy/FileActionBaseCopyCut.smali')
    data = smali.read_text(encoding='utf-8')
    marker = 'copyCut setSceneAction skipped, patched'
    if f'"{marker}"' in data:
        return
    method = _fm_only(
        [
            m for m in _FM_METHOD_RE.finditer(data)
            if m['sig'].endswith('()V') and ' static ' not in f' {m["sig"]} '
            and any(call in m['body'] for call in scene_calls)
        ],
        'FileActionBaseCopyCut method calling setSceneAction',
    )
    body = (
        '    .locals 2\n'
        '\n'
        '    const-string v0, "FileActionBaseCopyCut"\n'
        '\n'
        f'    const-string v1, "{marker}"\n'
        '\n'
        f'    invoke-static {{v0, v1}}, {_FM_LOG_D}\n'
        '\n'
        '    return-void\n'
    )
    data = data[:method.start()] + f'.method {method["sig"]}\n{body}.end method' + data[method.end():]
    smali.write_text(data, encoding='utf-8')


def blob_fixup_filemanager_superapp_zip_preview(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return
    # Clicking an archive in the SuperApp (Downloads/app sources) list goes
    # through the generic open path, which fails on LineageOS. Launch the
    # CompressPreview activity (CompressPreviewApi.startCompressPreviewActivity)
    # directly for zip-type files instead.
    lambda_anchor = 'c = "com.filemanager.superapp.ui.superapp.SuperListFragment$onItemClickOrDoubleClick$1$1$1"'
    smali = _fm_only(_fm_find_smali(tmp_dir, lambda_anchor), 'SuperListFragment item click coroutine')
    data = smali.read_text(encoding='utf-8')
    marker = 'SuperApp archive preview direct'
    if f'"{marker}"' in data:
        return

    apis = []
    for path in _fm_find_smali(tmp_dir, '"oppo.intent.action.ACTION_COMPRESS_PREVIEW"'):
        api_data = path.read_text(encoding='utf-8')
        for m in _FM_METHOD_RE.finditer(api_data):
            sig = re.fullmatch(r'public (?:final )?(\w+)\(Landroid/app/Activity;(L[^;]+;)I\)V', m['sig'])
            if sig and 'ACTION_COMPRESS_PREVIEW' in m['body']:
                apis.append((api_data, m, sig))
    api_data, api_method, api_sig = _fm_only(apis, 'CompressPreviewApi.startCompressPreviewActivity(Activity, file, flags)')
    api = _fm_class_desc(api_data)
    open_method, bean = api_sig.group(1), api_sig.group(2)
    api_instance = re.search(rf'(?m)^\.field public static final (\w+):{re.escape(api)}$', api_data)
    local_type = re.search(rf'invoke-virtual \{{p2\}}, {re.escape(bean)}->(\w+)\(\)I', api_method['body'])
    if not api_instance or not local_type:
        raise ValueError('FileManager CompressPreviewApi instance/localType getter not found')

    cls = _fm_class_desc(data)
    bean_field = _fm_only(re.findall(rf'(?m)^\.field [^\n]*?(\S+):{re.escape(bean)}$', data), 'click coroutine file field')
    activity_field = _fm_only(
        re.findall(r'(?m)^\.field [^\n]*?(\S+):Landroidx/fragment/app/FragmentActivity;$', data),
        'click coroutine activity field',
    )
    invoke_suspend = _fm_only(
        [m for m in _FM_METHOD_RE.finditer(data) if m['sig'] == 'public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;'],
        'click coroutine invokeSuspend()',
    )
    body = invoke_suspend['body']
    locals_count = re.match(r'\s*\.locals (\d+)', body)
    if not locals_count or int(locals_count.group(1)) < 4:
        raise ValueError('FileManager click coroutine invokeSuspend() has too few registers')
    first_call = re.search(
        rf'    iget (v\d+), p0, {re.escape(cls)}->\w+:I\n(?:.*\n)*?    if-eqz \1, :(\w+)\n', body
    )
    unit = re.findall(r'sget-object p0, (L[^;]+;)->(\w+):\1\n\n    return-object p0\n', body)
    if not first_call or not unit:
        raise ValueError('FileManager click coroutine state machine / Unit not found')
    anchor_re = re.compile(
        rf'    :{first_call.group(2)}\n    invoke-static \{{p1\}}, L[^;]+;->\w+\(Ljava/lang/Object;\)V\n\n'
    )
    anchor = _fm_only(list(anchor_re.finditer(body)), 'click coroutine first-invocation anchor')
    unit_cls, unit_field = unit[-1]
    insert = (
        f'    iget-object p1, p0, {cls}->{bean_field}:{bean}\n'
        '\n'
        f'    invoke-virtual {{p1}}, {bean}->{local_type.group(1)}()I\n'
        '\n'
        '    move-result p1\n'
        '\n'
        # MimeTypeHelper.COMPRESSED_TYPE ("zip"/"ozip"/...)
        '    const/16 v1, 0x80\n'
        '\n'
        '    if-ne p1, v1, :cond_superapp_archive_skip\n'
        '\n'
        '    const-string p1, "SuperListFragment"\n'
        '\n'
        f'    const-string v1, "{marker}"\n'
        '\n'
        f'    invoke-static {{p1, v1}}, {_FM_LOG_D}\n'
        '\n'
        f'    sget-object p1, {api}->{api_instance.group(1)}:{api}\n'
        '\n'
        f'    iget-object v1, p0, {cls}->{activity_field}:Landroidx/fragment/app/FragmentActivity;\n'
        '\n'
        f'    iget-object v2, p0, {cls}->{bean_field}:{bean}\n'
        '\n'
        '    const/high16 v3, 0x18000000\n'
        '\n'
        f'    invoke-virtual {{p1, v1, v2, v3}}, {api}->{open_method}(Landroid/app/Activity;{bean}I)V\n'
        '\n'
        f'    sget-object p0, {unit_cls}->{unit_field}:{unit_cls}\n'
        '\n'
        '    return-object p0\n'
        '\n'
        '    :cond_superapp_archive_skip\n'
        '\n'
    )
    start = invoke_suspend.start('body') + anchor.end()
    data = data[:start] + insert + data[start:]
    smali.write_text(data, encoding='utf-8')


def blob_fixup_filemanager_skip_osense_scene_actions(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return
    # PerformanceManager.setSceneAction() (u6/b.f() in 16.0.8,
    # com/filemanager/common/cpu/PerformanceManager.f() in 16.0.10) talks to the
    # OEM osense/orms services, which are absent on LineageOS. Make it a no-op.
    path, data, method, _ = _fm_scene_action(tmp_dir)
    if '"setSceneAction return, patched"' in method['body']:
        return
    body = (
        '    .locals 2\n'
        '\n'
        '    const-string v0, "PerformanceManager"\n'
        '\n'
        '    const-string v1, "setSceneAction return, patched"\n'
        '\n'
        f'    invoke-static {{v0, v1}}, {_FM_LOG_D}\n'
        '\n'
        '    return-void\n'
    )
    data = data[:method.start()] + f'.method {method["sig"]}\n{body}.end method' + data[method.end():]
    path.write_text(data, encoding='utf-8')


def blob_fixup_filemanager_safecheck_direct(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return
    # JavaFileHelper.safeCheck(method, default) runs `method` inside
    # runBlocking { withTimeout(500) { ... } } and returns `default` on
    # timeout, which makes archive extraction checks fail on LineageOS. Call
    # `method` directly and only fall back to `default` when it throws.
    anchor = '"safeCheck failed: default="'
    path = _fm_only(_fm_find_smali(tmp_dir, anchor), 'JavaFileHelper class (safeCheck log)')
    data = path.read_text(encoding='utf-8')
    candidates = []
    for m in _FM_METHOD_RE.finditer(data):
        sig = re.fullmatch(
            r'public (?:final )?\w+\((L[^;]+;)Ljava/lang/Object;\)Ljava/lang/Object;', m['sig']
        )
        if sig and anchor in m['body']:
            candidates.append((m, sig.group(1)))
    method, function0 = _fm_only(candidates, 'JavaFileHelper.safeCheck(Function0, Object)')
    if '"safeCheck direct"' in method['body']:
        return
    body = (
        '    .locals 3\n'
        '\n'
        '    const-string v0, "JavaFileHelper"\n'
        '\n'
        '    const-string v1, "safeCheck direct"\n'
        '\n'
        f'    invoke-static {{v0, v1}}, {_FM_LOG_D}\n'
        '\n'
        '    :try_start_0\n'
        f'    invoke-interface {{p1}}, {function0}->invoke()Ljava/lang/Object;\n'
        '\n'
        '    move-result-object v1\n'
        '    :try_end_0\n'
        '    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0\n'
        '\n'
        '    return-object v1\n'
        '\n'
        '    :catch_0\n'
        '    move-exception v1\n'
        '\n'
        '    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;\n'
        '\n'
        '    move-result-object v1\n'
        '\n'
        '    new-instance v2, Ljava/lang/StringBuilder;\n'
        '\n'
        '    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V\n'
        '\n'
        '    const-string p0, "safeCheck failed: default="\n'
        '\n'
        '    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
        '\n'
        '    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;\n'
        '\n'
        '    const-string p0, ", "\n'
        '\n'
        '    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
        '\n'
        '    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n'
        '\n'
        '    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n'
        '\n'
        '    move-result-object v1\n'
        '\n'
        f'    invoke-static {{v0, v1}}, {_FM_LOG_D}\n'
        '\n'
        '    return-object p2\n'
    )
    data = data[:method.start()] + f'.method {method["sig"]}\n{body}.end method' + data[method.end():]
    path.write_text(data, encoding='utf-8')


blob_fixups: blob_fixups_user_type = {
    # Same as the LineageOS infiniti tree does for its ODM camera libs.
    'odm/lib64/libAncHumanSegFigureFusion.so': blob_fixup()
        .clear_symbol_version('AHardwareBuffer_allocate')
        .clear_symbol_version('AHardwareBuffer_describe')
        .clear_symbol_version('AHardwareBuffer_lock')
        .clear_symbol_version('AHardwareBuffer_release')
        .clear_symbol_version('AHardwareBuffer_unlock'),
    # Overrides the sm8850-common copy: opluscamera.mk is inherited first.
    'vendor/etc/public.libraries.txt': blob_fixup()
        .add_line_if_missing('libarcsoft_hdr_couple_api.so')
        .add_line_if_missing('libarcsoft_high_dynamic_range_couple.so')
        .add_line_if_missing('libarcsoft_smart_denoise.so')
        .add_line_if_missing('libarcsoft_turbo_hdr_raw.so')
        .add_line_if_missing('libarcsoft_turbo_raw.so')
        .add_line_if_missing('libarcsoft_qnnhtp.so')
        .add_line_if_missing('libQnnHtp.so')
        .add_line_if_missing('libQnnSystem.so')
        .add_line_if_missing('libQnnHtpV81Stub.so')
        .add_line_if_missing('libQnnGpu.so'),
    'system_ext/lib64/libNativeWinBuffExchange.so': blob_fixup()
        .call(blob_fixup_nativewinbuff_android17),
    # The stock camera extension has no dynamic imports from provider-V3 or
    # device-V3. Android 17's libcameraservice depends on their V4 libraries.
    'system_ext/lib64/libcsextimpl.so': blob_fixup()
        .remove_needed('android.hardware.camera.provider-V3-ndk.so')
        .remove_needed('android.hardware.camera.device-V3-ndk.so'),
    'system_ext/lib64/libAPSClient-cmd-jni.so': blob_fixup()
        .call(blob_fixup_apsclient_force_java_heif),
    'system_ext/framework/com.oplus.camera.unit.sdk.jar': blob_fixup()
        .apktool_unpack('patches-sdk')
        .patch_dir('patches-sdk')
        .call(blob_fixup_camera_unit_facebeauty_probe_path)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/OplusCamera/OplusCamera.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_font)
        .call(blob_fixup_opluscamera_blur_seginit_guard)
        .call(blob_fixup_strip_oem_permissions)
        .apktool_pack()
        .stripzip(),
    'system_ext/app/SystemUIPlugin/SystemUIPlugin.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_oplus_camera_system_properties)
        .call(blob_fixup_systemuiplugin_plugin_context_inflater)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/OppoGallery2/OppoGallery2.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_oppogallery_op15_native_libs)
        .call(blob_fixup_oppogallery_receiver_flags)
        .call(blob_fixup_oppogallery_wallpaper_attach_intent)
        .call(blob_fixup_oppogallery_safe_box_custom_flag)
        .call(blob_fixup_oppogallery_google_photos_consent_on_verify_failure)
        .call(blob_fixup_oppogallery_google_photos_launch_consent_after_verify_failure)
        .call(blob_fixup_oppogallery_hide_google_photos_backup_settings)
        .call(blob_fixup_oppogallery_system_share_helper)
        .call(blob_fixup_strip_oem_permissions)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/StdID/StdID.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_stdid_receiver_flags)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/PhoneManager/PhoneManager.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_phonemanager_secure_settings_permission)
        .call(blob_fixup_phonemanager_settings_category)
        .call(blob_fixup_phonemanager_permission_controller_package)
        .apktool_pack()
        .stripzip(),
    'system_ext/app/SafeCenter/SafeCenter.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_safecenter_receiver_flags)
        .call(blob_fixup_safecenter_olock_support)
        .call(blob_fixup_safecenter_olock_theft_dark_theme)
        .apktool_pack()
        .stripzip(),
    'product/app/AONService/AONService.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_manifest)
        .call(blob_fixup_aonservice_settings_category)
        .apktool_pack()
        .stripzip(),
    'product/priv-app/AIUnit/AIUnit.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_manifest)
        .call(blob_fixup_aiunit_settings_category)
        .call(blob_fixup_aiunit_settings_search)
        .apktool_pack()
        .stripzip(),
    'system_ext/etc/permissions/vendor-oplus-hardware-cryptoeng.xml': blob_fixup()
        .call(blob_fixup_cryptoeng_permissions_xml),
    'odm/etc/permissions/vendor-oplus-hardware-cryptoeng.xml': blob_fixup()
        .call(blob_fixup_cryptoeng_permissions_xml),
    'odm/etc/init/vendor.oplus.hardware.cryptoeng@1.0-service_FDE.rc': blob_fixup()
        .call(blob_fixup_cryptoeng_init_rc),
    'odm/etc/vintf/manifest/manifest_oplus_cryptoeng.xml': blob_fixup()
        .call(blob_fixup_cryptoeng_manifest),
    'system_ext/app/FileManager/FileManager.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_filemanager_safecheck_direct)
        .call(blob_fixup_filemanager_select_dir_current_path_fallback)
        .call(blob_fixup_filemanager_cut_skip_k0_when_same_disk)
        .call(blob_fixup_filemanager_copycut_skip_osense_scene)
        .call(blob_fixup_filemanager_superapp_zip_preview)
        .call(blob_fixup_filemanager_skip_osense_scene_actions)
        .apktool_pack()
        .stripzip(),
    'system_ext/app/Melody/Melody.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_oplus_camera_system_properties)
        .call(blob_fixup_strip_oem_permissions)
        .call(blob_fixup_melody_repackaging_detector)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/UMS/UMS.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_ums_activity_watcher_permission)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/OplusExSystemService/OplusExSystemService.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/DCS/DCS.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/FileEncryption/FileEncryption.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_opluscamera_uses_library)
        .call(blob_fixup_fileencryption_secure_settings_permission)
        .call(blob_fixup_fileencryption_biometric_enrollment_checks)
        .call(blob_fixup_oplus_camera_system_properties)
        .apktool_pack()
        .stripzip(),
    'system_ext/app/SecurityPermission/SecurityPermission.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_full)
        .call(blob_fixup_securitypermission_safe_permissions)
        .apktool_pack()
        .stripzip(),
}  # fmt: skip

namespace_imports = [
    'vendor/oneplus/infiniti',
    'vendor/oneplus/sm8850-common',
    'hardware/oplus',
]

module = ExtractUtilsModule(
    'infiniti-camera',
    'oneplus',
    device_rel_path='device/oneplus/infiniti-camera',
    blob_fixups=blob_fixups,
    lib_fixups=lib_fixups,
    namespace_imports=namespace_imports,
)

if __name__ == '__main__':
    utils = ExtractUtils.device(module)
    utils.run()
    
from pathlib import Path
import os
import re


CUSTOM_SOONG_BEGIN = "// BEGIN INFINITI-CAMERA CUSTOM SOONG MODULES"
CUSTOM_SOONG_END = "// END INFINITI-CAMERA CUSTOM SOONG MODULES"


def write_custom_android_bp():
    top = Path(os.environ.get(
        "ANDROID_BUILD_TOP",
        Path(__file__).resolve().parents[3],
    ))

    android_bp = top / "vendor" / "oneplus" / "infiniti-camera" / "Android.bp"
    if not android_bp.exists():
        return

    custom_block = f"""
{CUSTOM_SOONG_BEGIN}

dex_import {{
    name: "oplus-services",
    jars: ["proprietary/system/framework/oplus-services.jar"],
    system_ext_specific: false,
}}

prebuilt_overlay {{
    name: "aon.frameworkres.overlay.product",
    src: ":aon_frameworkres_overlay_apk",
    filename: "aon.frameworkres.overlay.product.apk",
    product_specific: true,
}}

{CUSTOM_SOONG_END}
"""

    old_text = android_bp.read_text()
    new_text = re.sub(
        rf"\n?{re.escape(CUSTOM_SOONG_BEGIN)}.*?{re.escape(CUSTOM_SOONG_END)}\n?",
        "",
        old_text,
        flags=re.S,
    ).rstrip() + "\n" + custom_block

    if new_text != old_text:
        android_bp.write_text(new_text)


write_custom_android_bp()

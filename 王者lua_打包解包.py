# -*- coding: utf-8 -*-
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

for i in range(10):
    print("诚铭nb，频道@ASGA8")
    time.sleep(0.01)

OPCODE_MAP_TEXT = '{\r\n  "28": 1,\r\n  "29": 2,\r\n  "30": 3,\r\n  "32": 5,\r\n  "0": 10,\r\n  "36": 9,\r\n  "24": 34,\r\n  "33": 6,\r\n  "34": 7,\r\n  "26": 36,\r\n  "27": 0,\r\n  "2": 12,\r\n  "3": 13,\r\n  "4": 14,\r\n  "5": 15,\r\n  "6": 16,\r\n  "7": 17,\r\n  "8": 18,\r\n  "9": 19,\r\n  "10": 20,\r\n  "18": 28,\r\n  "11": 21,\r\n  "13": 23,\r\n  "12": 22,\r\n  "14": 24,\r\n  "15": 25,\r\n  "16": 26,\r\n  "17": 27,\r\n  "22": 32,\r\n  "21": 31,\r\n  "23": 33,\r\n  "1": 11,\r\n  "25": 35,\r\n  "19": 29,\r\n  "20": 30,\r\n  "35": 8,\r\n  "31": 4,\r\n  "37": 37\r\n}'
MAP = {int(k): v for k, v in json.loads(OPCODE_MAP_TEXT).items()}

MASK = 0xffffffff
DELTA = 0x9e3779b9
KEY = struct.unpack('<4I', b'pandora'.ljust(16, b'\0'))


def mx(z, y, total, p, e):
    return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4))
            ^ ((total ^ y) + (KEY[(p & 3) ^ e] ^ z))) & MASK


def decrypt(data):
    if len(data) % 4 or len(data) < 8:
        raise ValueError('Invalid XXTEA size')
    words = list(struct.unpack('<%dI' % (len(data) // 4), data))
    last = len(words) - 1
    total = ((6 + 52 // len(words)) * DELTA) & MASK
    y = words[0]
    while total:
        e = (total >> 2) & 3
        for p in range(last, 0, -1):
            z = words[p - 1]
            words[p] = (words[p] - mx(z, y, total, p, e)) & MASK
            y = words[p]
        z = words[last]
        words[0] = (words[0] - mx(z, y, total, 0, e)) & MASK
        y = words[0]
        total = (total - DELTA) & MASK
    length = words[-1]
    raw = struct.pack('<%dI' % len(words), *words)
    if not len(raw) - 7 <= length <= len(raw) - 4:
        raise ValueError('Invalid decoded length %d' % length)
    return raw[:length]


def encrypt(data):
    raw = data + b'\0' * ((-len(data)) % 4) + struct.pack('<I', len(data))
    words = list(struct.unpack('<%dI' % (len(raw) // 4), raw))
    last = len(words) - 1
    total = 0
    z = words[last]
    for _ in range(6 + 52 // len(words)):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(last):
            y = words[p + 1]
            words[p] = (words[p] + mx(z, y, total, p, e)) & MASK
            z = words[p]
        y = words[0]
        words[last] = (words[last] + mx(z, y, total, last, e)) & MASK
        z = words[last]
    return struct.pack('<%dI' % len(words), *words)


class Chunk:
    def __init__(self, data):
        if len(data) < 12 or data[:8] != b'\x1bLua\x51\x00\x01\x04':
            raise ValueError('需要小端 Lua 5.1 字节码，且 int 长度为 4。普通 .lua 源码不能直接打包。')
        if data[8] not in (4, 8) or data[9:12] != b'\x04\x08\x00':
            raise ValueError('不支持此 Lua 字节码布局：需要 4 字节指令、8 字节浮点数。')
        self.data, self.pos = data, 12
        self.strsize, self.numsize = data[8], data[10]
        self.functions, self.strings = [], []
        self.readfunc('main', 0)
        if self.pos != len(data):
            raise ValueError('Lua 字节码末尾存在未识别的数据。')

    def take(self, count):
        if count < 0 or count > len(self.data) - self.pos:
            raise ValueError('Lua 字节码被截断，或长度字段不正确。')
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def u(self):
        return struct.unpack('<I', self.take(4))[0]

    def count(self, minimum):
        value = self.u()
        if value > (len(self.data) - self.pos) // minimum:
            raise ValueError('Lua 元素数量超出文件边界。')
        return value

    def string(self):
        start = self.pos
        value = self.take(int.from_bytes(self.take(self.strsize), 'little'))
        if value and value[-1] != 0:
            raise ValueError('Lua 字符串缺少结尾零字节。')
        return start, self.pos, value[:-1] if value else b''

    def readfunc(self, name, depth):
        if depth > 100 or len(self.functions) >= 100000:
            raise ValueError('Lua 函数嵌套或数量超出工具限制。')
        self.string()
        self.take(12)  # 行号范围和函数标记
        count = self.count(4)
        offset = self.pos
        codes = [self.u() for _ in range(count)]
        self.functions.append({'name': name, 'offset': offset, 'codes': codes})
        for index in range(self.count(1)):
            kind = self.take(1)[0]
            if kind == 1:
                self.take(1)
            elif kind == 3:
                self.take(self.numsize)
            elif kind == 4:
                start, end, value = self.string()
                self.strings.append({'function': name, 'index': index,
                                     'start': start, 'end': end, 'value': value})
            elif kind != 0:
                raise ValueError('未知 Lua 常量类型：%d' % kind)
        for index in range(self.count(1)):
            self.readfunc(name + '/' + str(index), depth + 1)
        self.take(4 * self.count(4))
        for _ in range(self.count(self.strsize + 8)):
            self.string()
            self.take(8)
        for _ in range(self.count(self.strsize)):
            self.string()


MAX_BYTES = 64 * 1024 * 1024
FORMAT = 'pandora-unpack-v1'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError('输入不是文件：' + str(path))
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('输入超过 64 MiB，已停止。')
    return path.read_bytes()


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(value)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf8')


def convert(data, to_custom):
    mapping = {v: k for k, v in MAP.items()} if to_custom else MAP
    result = bytearray(data)
    for function in Chunk(data).functions:
        extra = False
        for index, code in enumerate(function['codes']):
            if extra:  # SETLIST 的 C=0 时，下一项是扩展数据。
                extra = False
                continue
            old = code & 63
            if old not in mapping:
                raise ValueError('指令映射不兼容：%s 第 %d 条指令。' % (function['name'], index))
            standard = old if to_custom else mapping[old]
            struct.pack_into('<I', result, function['offset'] + 4 * index, (code & ~63) | mapping[old])
            if standard == 34 and ((code >> 14) & 511) == 0:
                extra = True
        if extra:
            raise ValueError('SETLIST 扩展指令不完整。')
    return bytes(result)


def decode_resource(value):
    if not value.startswith(b'PDCODE'):
        raise ValueError('输入没有 PDCODE 文件头，请选择本项目的 .bytes 资源。')
    custom = decrypt(value[6:])
    Chunk(custom)
    if b'PDCODE' + encrypt(custom) != value:
        raise ValueError('解密后重新加密不一致，拒绝继续。')
    return custom


def encode_resource(custom):
    Chunk(custom)
    # 转换后再转回，确认指令映射兼容。
    if convert(convert(custom, False), True) != custom:
        raise ValueError('指令往返转换不一致。')
    result = b'PDCODE' + encrypt(custom)
    if decrypt(result[6:]) != custom:
        raise ValueError('加解密校验失败。')
    return result


def overlay_record(custom):
    candidates = [s for s in Chunk(custom).strings
                  if b'createSceneOverlay' in s['value'] and b'__rtdSceneOverlay' in s['value']
                  and b'const U=CS.UnityEngine' in s['value']]
    if len(candidates) > 1:
        raise ValueError('发现多个界面脚本，无法唯一识别；请使用项目原有 build.py。')
    if not candidates:
        return None
    candidates[0]['value'].decode('utf8')
    return candidates[0]


def replace_overlay(custom, record, javascript):
    javascript.decode('utf8')
    if not javascript.strip() or b'\0' in javascript:
        raise ValueError('界面脚本为空或包含零字节。')
    old = Chunk(custom)
    value = len(javascript + b'\0').to_bytes(old.strsize, 'little') + javascript + b'\0'
    patched = custom[:record['start']] + value + custom[record['end']:]
    new = Chunk(patched)
    if [f['codes'] for f in old.functions] != [f['codes'] for f in new.functions]:
        raise ValueError('替换脚本改变了 Lua 指令。')
    return patched


def legacy_block_bounds(javascript, begin, end):
    starts, ends = javascript.count(begin), javascript.count(end)
    if starts != ends or starts > 1:
        raise ValueError('旧界面代码标记不完整或重复，已停止打包以保留原内容。')
    if not starts:
        return None
    first, last = javascript.index(begin), javascript.index(end)
    if last < first:
        raise ValueError('旧界面代码标记顺序异常，已停止打包。')
    return first, last + len(end)


def erase_legacy_block(javascript, first, last):
    while last < len(javascript) and javascript[last:last + 1] in (b' ', b'\t', b'\r', b'\n'):
        last += 1
    return javascript[:first] + javascript[last:]


def remove_previous_pack_labels(javascript):
    # 只清理旧版工具插入的代码。
    bounds = legacy_block_bounds(javascript, b'/* CM_PACK_WATERMARK_BEGIN */',
                                 b'/* CM_PACK_WATERMARK_END */')
    if bounds:
        block = javascript[bounds[0]:bounds[1]].replace(b'\r\n', b'\n').strip()
        if sha(block) != 'd3e2827a223f6826a6ad38217ae05baf2aa28e14b049ad34043b3f10253ba5d9':
            raise ValueError('旧水印代码含额外改动，已停止打包以保留你的代码。')
        javascript = erase_legacy_block(javascript, *bounds)
    bounds = legacy_block_bounds(javascript, b'/* RTD_CONFIG_UI_BEGIN */',
                                 b'/* RTD_CONFIG_UI_END */')
    if not bounds:
        return javascript
    first, last = bounds
    block = javascript[first:last].decode('utf8')
    tokens = ('const uiConfig=', 'const configuredUI=createConfiguredUI(root.rect,')
    token = next((value for value in tokens if value in block), None)
    if token is None:
        raise ValueError('旧界面配置已变更，无法自动清理。请检查解包后的界面 JS。')
    start = block.index(token) + len(token)
    while start < len(block) and block[start].isspace():
        start += 1
    try:
        config, count = json.JSONDecoder().raw_decode(block[start:])
    except ValueError:
        raise ValueError('旧界面配置无法读取，已停止打包以保留原内容。') from None
    end = start + count
    if (not isinstance(config, dict) or not isinstance(config.get('elements'), list)
            or any(not isinstance(item, dict) for item in config['elements'])):
        raise ValueError('旧界面配置格式异常，已停止打包。')
    remaining = [item for item in config['elements'] if item.get('id') != 'footer_note']
    if len(remaining) == len(config['elements']):
        return javascript
    config['elements'] = remaining
    # 只有未改过的空模板可以整段删除，用户加的代码和配置要留下。
    template = (block[:start] + '{}' + block[end:]).replace('\r\n', '\n').strip()
    known_templates = {
        'cdf83aac926acb5582609a6ab9eadb129076a29b4f61709f8a0dbbefb8537049',
        '6c3292f5e6a6905fb89085e3d78fd903f0cd79ebfa8d547151784fddde213d54',
    }
    if (not remaining and set(config) == {'version', 'elements'} and config['version'] == 1
            and sha(template.encode('utf8')) in known_templates):
        return erase_legacy_block(javascript, first, last)
    encoded = json.dumps(config, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    encoded = encoded.replace('/', r'\/')
    replacement = (block[:start] + encoded + block[end:]).encode('utf8')
    return javascript[:first] + replacement + javascript[last:]


def clean_previous_pack_labels(custom):
    record = overlay_record(custom)
    if record is None:
        return custom
    javascript = remove_previous_pack_labels(record['value'])
    if javascript == record['value']:
        return custom
    return replace_overlay(custom, record, javascript)


def unpack(source, destination):
    original = read(source)
    custom = decode_resource(original)
    standard = convert(custom, False)
    if convert(standard, True) != custom:
        raise ValueError('指令往返转换失败。')
    record = overlay_record(custom)
    manifest = {'format': FORMAT, 'source_name': Path(source).name,
                'source_sha256': sha(original), 'source_bytes': len(original),
                'custom_sha256': sha(custom), 'standard_sha256': sha(standard),
                'lua_header_hex': custom[:12].hex(),
                'opcode_map_sha256': sha(OPCODE_MAP_TEXT.encode('utf8')),
                'functions': len(Chunk(custom).functions), 'roundtrip_identical': True,
                'overlay': None}
    if record:
        manifest['overlay'] = {'file': 'overlay_payload.js', 'sha256': sha(record['value']),
                               'function': record['function'], 'constant_index': record['index']}
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    write_new(destination / 'custom.luac', custom)
    write_new(destination / 'standard.luac', standard)
    if record:
        write_new(destination / 'overlay_payload.js', record['value'])
    write_new(destination / 'manifest.json', json_bytes(manifest))
    write_new(destination / '解包说明.txt', (
        '解包后怎么用\n\n'
        + ('1. 用文本编辑器打开 overlay_payload.js，修改后保存。\n'
           '2. 回到工具，输入 2，再选择这个文件夹。\n'
           if record else
           '这个资源没有可编辑的界面 JS。\n'
           '要原样打包，回到工具选 2，再选择这个文件夹。\n')
        + '\n新的 .bytes 保存在这个文件夹旁边，终端会显示路径。\n\n'
        'custom.luac、standard.luac 和 manifest.json 请保留原样。\n'
        '.luac 是编译文件，不能当源码修改；工具不提供反编译。\n'
    ).encode('utf8'))
    return {'action': 'unpack', 'output': str(destination.resolve()), **manifest}


def pack(source, destination, standard=False):
    source = Path(source)
    changed = False
    expected = None
    if source.is_dir():
        if standard:
            raise ValueError('--standard 只用于单个标准 .luac 文件。')
        manifest = json.loads(read(source / 'manifest.json').decode('utf8'))
        if manifest.get('format') != FORMAT:
            raise ValueError('此目录不是本工具解包产生的目录。')
        custom = read(source / 'custom.luac')
        if sha(custom) != manifest.get('custom_sha256'):
            raise ValueError('custom.luac 已改变，请恢复原文件。此菜单支持修改 overlay_payload.js 后打包。')
        if manifest.get('opcode_map_sha256') != sha(OPCODE_MAP_TEXT.encode('utf8')):
            raise ValueError('当前指令映射与解包时不同。')
        overlay = manifest.get('overlay')
        if overlay is not None:
            record = overlay_record(custom)
            if not record or sha(record['value']) != overlay.get('sha256'):
                raise ValueError('模板中的界面脚本与清单不一致。')
            javascript = read(source / 'overlay_payload.js')
            changed = javascript != record['value']
            custom = replace_overlay(custom, record, javascript)
        if not changed:
            expected = manifest.get('source_sha256')
    else:
        custom = read(source)
        if standard:
            custom = convert(custom, True)
    prepared = clean_previous_pack_labels(custom)
    packed = encode_resource(prepared)
    if expected and sha(encode_resource(custom) if prepared != custom else packed) != expected:
        raise ValueError('未修改文件的回包哈希与原资源不一致。')
    write_new(destination, packed)
    return {'action': 'pack', 'output': str(Path(destination).resolve()), 'bytes': len(packed),
            'sha256': sha(packed), 'overlay_changed': changed,
            'roundtrip_identical_to_source': sha(packed) == expected if expected else None,
            'removed_legacy_labels': prepared != custom,
            'phone_tested': False}


def run_action(action, source, destination=None, standard=False):
    source = Path(source)
    if action != 'check':
        if not destination:
            raise ValueError('请设置输出路径。')
        destination = Path(destination)
        if source.resolve() == destination.resolve():
            raise ValueError('输入和输出不能相同。')
        if destination.exists():
            raise ValueError('输出已存在，请换一个名字，避免覆盖：' + str(destination))
    if action == 'unpack':
        return unpack(source, destination)
    if action == 'pack':
        return pack(source, destination, standard)
    value = read(source)
    if action == 'check':
        custom = decode_resource(value)
        standard_bytes = convert(custom, False)
        if encode_resource(convert(standard_bytes, True)) != value:
            raise ValueError('完整往返校验失败。')
        return {'action': action, 'file': str(source.resolve()), 'bytes': len(value),
                'sha256': sha(value), 'roundtrip_identical': True,
                'functions': len(Chunk(custom).functions)}
    if action == 'decrypt':
        result = decode_resource(value)
    elif action == 'encrypt':
        result = encode_resource(value)
    elif action in ('normalize', 'customize'):
        result = convert(value, action == 'customize')
    elif action == 'extract-js':
        custom = decode_resource(value) if value.startswith(b'PDCODE') else value
        record = overlay_record(custom)
        if not record:
            raise ValueError('没有检测到本项目的内嵌界面 JavaScript。')
        result = record['value']
    else:
        raise ValueError('不支持的操作：' + action)
    write_new(destination, result)
    return {'action': action, 'output': str(destination.resolve()), 'bytes': len(result), 'sha256': sha(result)}


class BackToMenu(Exception):
    pass


def clean_path(value):
    value = value.strip()
    if value.startswith('& '):
        value = value[2:].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    return Path(value).expanduser()


def suggested_output(source, action):
    source = Path(source)
    if action == 'unpack':
        candidate = source.with_name(source.stem + '_解包')
    elif action == 'extract-js':
        candidate = source.with_name(source.stem + '_界面.js')
    else:
        stem = source.stem
        if source.is_dir():
            manifest = json.loads(read(source / 'manifest.json').decode('utf8'))
            original_name = manifest.get('source_name')
            if isinstance(original_name, str) and Path(original_name).name == original_name:
                stem = Path(original_name).stem or stem
        candidate = source.with_name(stem + '_打包.bytes')
    original = candidate
    counter = 2
    while candidate.exists():
        candidate = original.with_name(original.stem + '_' + str(counter) + original.suffix)
        counter += 1
    return candidate


def validate_source(source, kind):
    source = source.resolve()
    if kind == 'folder':
        if source.is_file() and source.name in (
                'overlay_payload.js', 'manifest.json', 'custom.luac', 'standard.luac'):
            source = source.parent
        if not source.is_dir():
            raise ValueError('请选择解包得到的文件夹。还没解包的话，输入 q 返回，再选 1。')
        if not (source / 'manifest.json').is_file() or not (source / 'custom.luac').is_file():
            raise ValueError('这个文件夹不完整。请选择直接装着 manifest.json 和 custom.luac 的那一层。')
        manifest = json.loads(read(source / 'manifest.json').decode('utf8'))
        if not isinstance(manifest, dict) or manifest.get('format') != FORMAT:
            raise ValueError('这不是本工具解包的文件夹。输入 q 返回，先选 1 解包。')
        standard_path = source / 'standard.luac'
        if standard_path.is_file() and sha(read(standard_path)) != manifest.get('standard_sha256'):
            raise ValueError('standard.luac 已改变，请恢复原文件。此菜单支持修改 overlay_payload.js 后打包。')
        return source
    if not source.is_file():
        raise ValueError('找不到这个文件。请重新拖入文件，或右键文件“复制文件地址”后粘贴。')
    if kind == 'resource':
        with source.open('rb') as handle:
            header = handle.read(6)
        if header != b'PDCODE':
            raise ValueError('这个不是支持的资源文件。请选择本项目原来的 .bytes 文件，不要选 .py、.js 或 .lua。')
    return source


def find_candidates(kind, recent=None):
    candidates = []
    seen = set()

    def add(path):
        try:
            path = path.resolve()
            if path not in seen:
                seen.add(path)
                if path.exists():
                    candidates.append(path)
        except OSError:
            pass

    if recent is not None:
        add(recent)
    for base in dict.fromkeys((Path(__file__).resolve().parent, Path.cwd())):
        try:
            entries = sorted(base.iterdir(), key=lambda item: item.name.casefold())
            for path in entries:
                if kind == 'folder':
                    match = path.is_dir() and (path / 'manifest.json').is_file() and (path / 'custom.luac').is_file()
                elif kind == 'resource':
                    match = path.is_file() and path.suffix.lower() == '.bytes'
                else:
                    match = path.is_file() and path.name.lower() == kind + '.luac'
                if match:
                    add(path)
        except OSError:
            continue
    return candidates[:20]


def ask_source(kind, recent=None):
    noun = '文件夹' if kind == 'folder' else '文件'
    candidates = find_candidates(kind, recent)
    print('\n选择' + noun + '：')
    if candidates:
        for index, path in enumerate(candidates, 1):
            print('  {}. {}\n     {}'.format(index, path.name, path.parent))
    print('拖入' + noun + '或粘贴路径，输入 q 返回。')
    default = None
    if len(candidates) == 1 or (recent is not None and candidates and candidates[0] == recent.resolve()):
        default = 1
    while True:
        prompt = '输入编号或路径' + ('（直接回车选 1）' if default else '') + '：'
        value = input(prompt).strip()
        if value.lower() in ('q', '0', '取消'):
            raise BackToMenu()
        if not value:
            if default is None:
                print('还没有选' + noun + '，请输入编号或路径。')
                continue
            source = candidates[default - 1]
        elif value.isdigit():
            number = int(value)
            if not 1 <= number <= len(candidates):
                print('没有这个编号，请重新选择。')
                continue
            source = candidates[number - 1]
        else:
            source = clean_path(value)
        try:
            return validate_source(source, kind)
        except (OSError, ValueError) as error:
            show_error(error)


def show_error(error):
    if isinstance(error, PermissionError):
        message = '没有读写权限，或文件正被占用。请把资源复制到桌面文件夹后重试。'
    elif isinstance(error, FileNotFoundError):
        message = '找不到需要的文件，请检查解包文件夹是否完整。'
    elif isinstance(error, json.JSONDecodeError):
        message = 'manifest.json 已损坏。先备份改过的 JS，再重新解包原资源。'
    elif isinstance(error, UnicodeError):
        message = '文本编码不对，请把 JS 保存为 UTF-8 后重试。'
    elif isinstance(error, FileExistsError):
        message = '输出文件已存在，重试会自动换一个名字。'
    elif isinstance(error, (KeyError, TypeError, AttributeError)):
        message = '资源信息不完整，请重新解包原资源。'
    elif str(error).startswith('Invalid XXTEA') or str(error).startswith('Invalid decoded'):
        message = '这个资源已损坏或格式不匹配。请换用本项目完整的 .bytes 文件。'
    else:
        message = str(error)
    print('\n没能完成：' + message)


def show_result(result):
    print('\n' + '-' * 36)
    if result['action'] == 'unpack':
        print('解包完成：\n  ' + result['output'])
        if result.get('overlay'):
            print('修改 overlay_payload.js 并保存，再选 2 打包。其余文件保留原样。')
        else:
            print('没有可编辑的界面 JS；.luac 不能当文本修改。选 2 可原样打包。')
    elif result['action'] == 'pack':
        print('打包完成：\n  ' + result['output'])
        if result.get('overlay_changed'):
            print('已打包你修改的界面 JS。')
        if result.get('roundtrip_identical_to_source'):
            print('内容与原资源完全一致。')
        if result.get('removed_legacy_labels'):
            print('旧版本添加的打包水印已移除。')
    elif result['action'] == 'extract-js':
        print('已提取界面 JS：\n  ' + result['output'])
        print('要修改后打包，请先选 1 完整解包。')
    else:
        print('检查通过，解包再打包后与原文件一致：\n  ' + result['file'])
    print('-' * 36)


def perform(action, source, standard=False):
    destination = None if action == 'check' else suggested_output(source, action)
    print('\n处理中…')
    if destination is not None:
        print('保存到：' + str(destination))
    result = run_action(action, source, destination, standard)
    show_result(result)
    return result


HANDLED_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError,
                  RecursionError, OverflowError, struct.error)


def main():
    recent_folder = None
    print('\n打包 / 解包')
    print('选 1 解包，改好后选 2 打包。结果保存在原文件旁边。')
    while True:
        print('\n' + '=' * 36)
        print('  1. 解包文件')
        print('  2. 打包文件')
        print('  0. 退出')
        print('=' * 36)
        if recent_folder is not None:
            print('上次解包：' + str(recent_folder))
        try:
            choice = input('输入编号（回车选 1）：').strip()
            if choice.lower() in ('0', 'q'):
                print('已退出。')
                return 0
            if choice in ('', '1', '2'):
                is_unpack = choice != '2'
                kind = 'resource' if is_unpack else 'folder'
                source = ask_source(kind, None if is_unpack else recent_folder)
                result = perform('unpack' if is_unpack else 'pack', source)
                if is_unpack:
                    recent_folder = Path(result['output'])
            else:
                print('请选择 1、2 或 0。')
        except BackToMenu:
            print('已返回主菜单。')
        except (EOFError, KeyboardInterrupt):
            print('\n已退出。')
            return 0
        except HANDLED_ERRORS as error:
            show_error(error)


if __name__ == '__main__':
    sys.exit(main())

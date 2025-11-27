/**
 * mmnote v1.0.0 - my markdown note.
 * Copyright (c) 2025, mmnote.com. (MIT Licensed)
 * https://mmnote.com
 */
// 保存笔记的路径前缀
const SAVE_PATH = '_tmp';
// 有效的笔记名称格式(只允许字母、数字、下划线和连字符)
const VALID_NOTE_PATTERN = /^[a-zA-Z0-9_-]+$/;

/**
 * 使用 notePath 生成加密密钥
 * @param {string} notePath - 笔记路径
 * @returns {Promise<CryptoKey>} 加密密钥
 */
async function generateEncryptionKey(notePath) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(notePath);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);
  return await crypto.subtle.importKey(
    'raw',
    hashBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * 加密文本
 * @param {string} text - 要加密的文本
 * @param {CryptoKey} key - 加密密钥
 * @returns {Promise<string>} 加密后的base64字符串
 */
async function encryptText(text, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  const encryptedArray = new Uint8Array(encryptedData);
  const resultArray = new Uint8Array(iv.length + encryptedArray.length);
  resultArray.set(iv);
  resultArray.set(encryptedArray, iv.length);
  return btoa(String.fromCharCode(...resultArray));
}

/**
 * 解密文本
 * @param {string} encryptedText - 加密的base64字符串
 * @param {CryptoKey} key - 解密密钥
 * @returns {Promise<string>} 解密后的文本
 */
async function decryptText(encryptedText, key) {
  try {
    const encryptedArray = new Uint8Array(atob(encryptedText).split('').map(c => c.charCodeAt(0)));
    const iv = encryptedArray.slice(0, 12);
    const data = encryptedArray.slice(12);
    const decryptedData = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );
    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
  } catch (error) {
    console.error('解密失败:', error);
    return ''; // 解密失败返回空字符串
  }
}

/**
 * 处理所有传入的请求
 * @param {Request} request - 传入的请求对象
 * @returns {Response} 响应对象
 */
async function handleRequest(request) {
  const url = new URL(request.url);
  const pathParts = url.pathname.split('/').filter(Boolean);
  const noteName = pathParts[0];
  const action = pathParts[1];

  // 处理分享相关的请求
  if (noteName === 'share') {
    if (request.method === 'POST' && action) {
      try {
        const shareData = await request.json();
        await NOTES_KV.put('share_' + action, JSON.stringify(shareData));
        return new Response(null, { status: 200 });
      } catch (error) {
        return new Response('保存分享数据失败', { status: 500 });
      }
    } else if (request.method === 'GET' && action) {
      return await handleShareRequest(action);
    }
  }

  // 如果笔记名无效或不存在,生成随机名称并重定向
  if (!noteName || noteName.length > 64 || !VALID_NOTE_PATTERN.test(noteName)) {
    const randomNoteName = generateRandomNoteName();
    return Response.redirect(`${url.origin}/${randomNoteName}`, 302);
  }

  const notePath = `${SAVE_PATH}/${noteName}`;

  // 处理密码相关的请求
  if (action) {
    // 使用笔记名和固定盐值生成密码存储键
    const passwordKey = await generatePasswordKey(noteName);
    
    switch (action) {
      case 'password':
        if (request.method === 'POST') {
          const { password } = await request.json();
          // 为每个密码生成唯一盐值
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
          // 使用盐值和密码生成最终哈希
          const finalHash = await hashPasswordWithSalt(password, salt);
          // 存储盐值和哈希
          await NOTES_KV.put(passwordKey, JSON.stringify({
            hash: finalHash,
            salt: saltHex
          }));
          return new Response(null, { status: 200 });
        } else if (request.method === 'DELETE') {
          const { password } = await request.json();
          const storedData = await NOTES_KV.get(passwordKey);
          if (storedData) {
            const { hash, salt } = JSON.parse(storedData);
            const saltArray = new Uint8Array(salt.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            const checkHash = await hashPasswordWithSalt(password, saltArray);
            if (checkHash === hash) {
              await NOTES_KV.delete(passwordKey);
              return new Response(null, { status: 200 });
            }
          }
          return new Response('Invalid password', { status: 401 });
        }
        break;

      case 'password-check':
        const hasPassword = await NOTES_KV.get(passwordKey);
        return new Response(null, { status: hasPassword ? 200 : 404 });

      case 'password-verify':
        const { password } = await request.json();
        const storedData = await NOTES_KV.get(passwordKey);
        if (storedData) {
          const { hash, salt } = JSON.parse(storedData);
          const saltArray = new Uint8Array(salt.match(/.{2}/g).map(byte => parseInt(byte, 16)));
          const checkHash = await hashPasswordWithSalt(password, saltArray);
          if (checkHash === hash) {
            return new Response(null, { status: 200 });
          }
        }
        return new Response('Invalid password', { status: 401 });
    }
  }

  const raw = url.searchParams.has('raw');

  // 根据请求方法分发处理
  switch (request.method) {
    case 'POST':
      return await handlePostRequest(request, notePath);
    case 'GET':
      return raw || isCommandLineRequest(request) 
        ? await handleRawRequest(notePath) 
        : await handleGetRequest(notePath, noteName);
    default:
      return new Response('Method Not Allowed', { status: 405 });
  }
}

/**
 * 使用笔记名和固定盐值生成密码存储键
 * @param {string} noteName - 笔记名称
 * @returns {Promise<string>} 密码存储键
 */
async function generatePasswordKey(noteName) {
  const encoder = new TextEncoder();
  const data = encoder.encode(noteName + '_pwd_protected');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return '_secure_' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 使用盐值对密码进行哈希
 * @param {string} password - 原始密码
 * @param {Uint8Array} salt - 盐值
 * @returns {Promise<string>} 哈希后的密码
 */
async function hashPasswordWithSalt(password, salt) {
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  // 将密码和盐值连接
  const dataToHash = new Uint8Array(passwordData.length + salt.length);
  dataToHash.set(passwordData);
  dataToHash.set(salt, passwordData.length);
  
  // 进行哈希
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 处理POST请求 - 保存或删除笔记内容
 * @param {Request} request - POST请求对象
 * @param {string} notePath - 笔记保存路径
 * @returns {Response} 响应对象
 */
async function handlePostRequest(request, notePath) {
  const formData = await request.formData();
  const text = formData.get('text') || await request.text();

  // 如果内容为空,删除笔记
  if (text.trim().length === 0) {
    await handleDeleteRequest(notePath);
    return new Response('Note will be deleted', { status: 200 });
  } else {
    await saveNoteContent(notePath, text);
    return new Response(null, { status: 204 });
  }
}

/**
 * 处理GET请求 - 返回笔记的HTML页面
 * @param {string} notePath - 笔记路径
 * @param {string} noteName - 笔记名称
 * @returns {Response} HTML响应
 */
async function handleGetRequest(notePath, noteName) {
  const noteContent = await getNoteContent(notePath);
  const html = generateHTML(noteName, noteContent);
  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

/**
 * 处理原始内容请求 - 返回纯文本格式的笔记内容
 * @param {string} notePath - 笔记路径
 * @returns {Response} 文本响应
 */
async function handleRawRequest(notePath) {
  const noteContent = await getNoteContent(notePath);
  return noteContent
    ? new Response(noteContent, { headers: { 'Content-Type': 'text/plain' } })
    : new Response('404 Not Found', { status: 404 });
}

/**
 * 处理删除请求
 * @param {string} notePath - 要删除的笔记路径
 * @returns {Response} 响应对象
 */
async function handleDeleteRequest(notePath) {
  await deleteNoteContent(notePath);
  return new Response(null, { status: 204 });
}

/**
 * 生成随机笔记名称
 * @returns {string} 5位随机字符串
 */
function generateRandomNoteName() {
  const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
  return Array.from({ length: 5 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

/**
 * 检查是否为命令行请求
 * @param {Request} request - 请求对象
 * @returns {boolean} 是否为命令行请求
 */
function isCommandLineRequest(request) {
  const userAgent = request.headers.get('User-Agent') || '';
  return userAgent.startsWith('curl') || userAgent.startsWith('Wget');
}

function generateHTML(noteName, noteContent) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${noteName} - 在线笔记</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.9.0/build/styles/github.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.9.0/build/styles/github-dark.min.css" media="(prefers-color-scheme: dark)">
    <!-- 添加KaTeX依赖 -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
    <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/contrib/auto-render.min.js"></script>
    <!-- 添加Mermaid依赖 -->
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10.6.1/dist/mermaid.min.js"></script>
    <style>
      :root {
        --primary-color: #4e92d1;
        --secondary-color: #6c757d;
        --bg-color: #ffffff;
        --text-color: #333333;
        --border-color: #e0e0e0;
        --container-bg: #ffffff;
        --editor-bg: #f8f8f8;
        --shadow-color: rgba(0, 0, 0, 0.1);
        --hover-color: #f0f0f0;
        --link-color: #0366d6;
        --link-hover-color: #0969da;
        --link-visited-color: #6f42c1;
      }

      [data-theme="dark"] {
        --primary-color: #a2c2f5;
        --secondary-color: #9ca3af;
        --bg-color: #1a1a1a;
        --text-color: #f1f1f1;
        --border-color: #404040;
        --container-bg: #2a2a2a;
        --editor-bg: #333333;
        --shadow-color: rgba(0, 0, 0, 0.3);
        --hover-color: #3a3a3a;
        --link-color: #58a6ff;
        --link-hover-color: #79b8ff;
        --link-visited-color: #bc8cff;
      }

      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      body {
        margin: 0;
        background: var(--bg-color);
        color: var(--text-color);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        font-size: 16px;
        line-height: 1.6;
        transition: all 0.3s ease;
      }

      .container {
        width: 100%;
        max-width: 100%;
        margin: 0 auto;
        padding: 10px;
        min-height: 100vh;
        height: 100vh;
        display: flex;
        flex-direction: column;
        background-color: var(--container-bg);
      }

      .container.toolbar-hidden {
        padding: 10px 10px 10px 10px;
      }

      .container.toolbar-hidden .editor-container {
        height: calc(100vh - 20px);
      }

      @media (min-width: 1200px) {
        .container {
          max-width: 95%;
          box-shadow: 0 0 20px var(--shadow-color);
        }
      }

      .toolbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 15px;
        background: var(--editor-bg);
        border-radius: 12px;
        margin-bottom: 10px;
        gap: 10px;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
        flex-shrink: 0;
        transition: all 0.3s ease;
        cursor: grab;
      }

      /* 添加工具栏滚动条样式 */
      .toolbar::-webkit-scrollbar {
        height: 6px;
        width: 6px;
      }

      .toolbar::-webkit-scrollbar-track {
        background: transparent;
      }

      .toolbar::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 3px;
      }

      .toolbar::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      /* 拖动时的光标样式 */
      .toolbar.dragging {
        cursor: grabbing;
      }

      .toolbar.hidden {
        display: none;
      }

      .toolbar-left {
        display: flex;
        align-items: center;
        gap: 15px;
        flex-shrink: 0; /* 防止工具栏压缩 */
      }

      .toolbar-right {
        display: flex;
        align-items: center;
        gap: 15px;
        flex-shrink: 0; /* 防止工具栏压缩 */
      }

      .toolbar-divider {
        width: 1px;
        height: 20px;
        background-color: var(--border-color);
        margin: 0 2px;
      }

      .switch-label {
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        color: var(--text-color);
        font-size: 0.9rem;
      }

      .switch-label input[type="checkbox"] {
        width: 16px;
        height: 16px;
      }

      .mode-toggle {
        background: none;
        border: none;
        font-size: 1.2rem;
        cursor: pointer;
        padding: 8px;
        border-radius: 50%;
        transition: all 0.3s ease;
        color: var(--text-color);
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .mode-toggle:hover {
        background: var(--hover-color);
      }

      .mode-toggle .sun-icon,
      .mode-toggle .moon-icon {
        display: none;
      }

      [data-theme="dark"] .moon-icon {
        display: block;
      }

      [data-theme="light"] .sun-icon {
        display: block;
      }

      .icon-container {
        width: 20px;
        height: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .note-name {
        color: var(--primary-color);
        font-weight: 500;
        cursor: pointer;
        padding: 5px 10px;
        border-radius: 6px;
        transition: all 0.3s ease;
        display: flex;
        align-items: center;
        gap: 5px;
        transform-origin: left center;
      }

      .note-name:hover {
        background: var(--hover-color);
        transform: scale(1.1);
      }

      #save-status {
        color: var(--secondary-color);
        font-size: 0.9rem;
        margin-left: 10px;
      }

      .editor-container {
        display: grid;
        grid-template-columns: 1fr;
        gap: 15px;
        flex: 1;
        min-height: 0;
        margin: 0;
        position: relative;
        transition: all 0.3s ease;
      }

      /* 编辑器包装器 */
      .editor-wrapper {
        position: relative;
        width: 100%;
        height: 100%;
        display: flex;
        background: var(--editor-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        overflow: hidden;
        flex-direction: column;
      }

      /* 设置统一的行高和字符宽度 */
      .editor-wrapper textarea,
      .line-numbers span {
        line-height: 1.5;
        min-height: 1.5em;
        font-size: 14px;
        font-family: 'Consolas', 'Monaco', monospace;
        box-sizing: border-box;
        letter-spacing: 0;
      }

      .line-numbers {
        padding: 15px 2px 40px 2px;
        background: var(--editor-bg);
        border-right: 1px solid var(--border-color);
        color: var(--secondary-color);
        user-select: none;
        overflow: hidden;
        min-width: 28px;
        width: auto;
        display: flex;
        flex-direction: column;
        align-items: flex-end;
      }

      .line-numbers span {
        display: block;
        padding: 0 4px;
        min-width: 24px;
        text-align: right;
        white-space: nowrap;
      }

      .line-numbers.hidden {
        display: none;
      }

      /* 编辑器主体区域 */
      .editor-main {
        display: flex;
        flex: 1;
        overflow: hidden;
        position: relative;
      }

      /* 状态栏样式统一 */
      .status-bar,
      .preview-status-bar {
        position: relative;
        height: 25px;
        background: var(--editor-bg);
        border-top: 1px solid var(--border-color);
        display: flex;
        align-items: center;
        padding: 0 10px;
        font-size: 12px;
        color: var(--secondary-color);
        justify-content: space-between;
        overflow-x: auto;
        overflow-y: hidden;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
        white-space: nowrap;
        flex-shrink: 0;
      }

      /* 状态栏滚动条样式 */
      .status-bar::-webkit-scrollbar,
      .preview-status-bar::-webkit-scrollbar {
        height: 4px;
        width: 4px;
      }

      .status-bar::-webkit-scrollbar-track,
      .preview-status-bar::-webkit-scrollbar-track {
        background: transparent;
      }

      .status-bar::-webkit-scrollbar-thumb,
      .preview-status-bar::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 2px;
      }

      .status-bar::-webkit-scrollbar-thumb:hover,
      .preview-status-bar::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      .status-left,
      .preview-status-left {
        display: flex;
        align-items: center;
        flex-wrap: nowrap;
        min-width: min-content;
        gap: 8px;
        padding-right: 8px;
      }

      .status-right,
      .preview-status-right {
        display: flex;
        align-items: center;
        margin-left: auto;
        padding-left: 15px;
        flex-wrap: nowrap;
        min-width: min-content;
        gap: 8px;
      }

      /* 确保状态栏内容不会被截断 */
      .status-bar > div,
      .preview-status-bar > div {
        flex-shrink: 0;
      }

      .status-item,
      .preview-status-item {
        display: flex;
        align-items: center;
        gap: 5px;
        font-family: 'Consolas', 'Monaco', monospace;
        white-space: nowrap;
        color: var(--secondary-color);
      }

      .status-item label,
      .preview-status-item label {
        display: flex;
        align-items: center;
        gap: 4px;
        cursor: pointer;
        font-family: inherit;
        font-size: inherit;
        color: var(--secondary-color);
      }

      .status-item input[type="checkbox"],
      .preview-status-item input[type="checkbox"] {
        width: 14px;
        height: 14px;
        cursor: pointer;
        margin: 0;
      }

      .status-item span,
      .preview-status-item span {
        color: var(--secondary-color);
      }

      .editor-container textarea {
        flex: 1;
        height: 100%;
        padding: 15px 10px;
        border: none;
        border-radius: 0;
        background: var(--editor-bg);
        color: var(--text-color);
        resize: none;
        tab-size: 4;
        -moz-tab-size: 4;
        white-space: pre-wrap;
        word-wrap: break-word;
        overflow-wrap: break-word;
        overflow-x: hidden;
        width: 100%;
        transition: all 0.3s ease;
      }

      .editor-container textarea:focus {
        outline: none;
      }

      .editor-container.preview-mode {
        grid-template-columns: 1fr 1fr;
      }

      .preview-container {
        display: none;
        height: 100%;
        padding: 0;  /* 移除padding */
        border-radius: 8px;
        border: 1px solid var(--border-color);
        background: var(--editor-bg);
        color: var(--text-color);
        overflow: hidden;  /* 改为hidden，防止整体滚动 */
        position: relative;
        -webkit-user-select: none;  /* Safari */
        -ms-user-select: none;      /* IE 10+ */
        user-select: none;          /* Standard syntax */
      }

      /* 添加预览内容容器样式 */
      .preview-content {
        height: calc(100% - 25px);  /* 减去状态栏高度 */
        padding: 10px 12px;
        overflow-y: auto;
        overflow-x: hidden;
        -webkit-user-select: text;  /* Safari */
        -ms-user-select: text;      /* IE 10+ */
        user-select: text;          /* Standard syntax */
      }

      /* 预览区状态栏样式 */
      .preview-status-bar {
        position: absolute;
        bottom: 0;
        left: 0;
        right: 0;
        height: 25px;
        background: var(--editor-bg);
        border-top: 1px solid var(--border-color);
        display: flex;
        align-items: center;
        padding: 0 10px;
        font-size: 12px;
        color: var(--secondary-color);
        z-index: 1;
        justify-content: space-between;
        min-width: 100%;
        white-space: nowrap;
      }

      .preview-status-left {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-shrink: 0;
      }

      .preview-status-right {
        display: flex;
        align-items: center;
        gap: 15px;
        flex-shrink: 0;
        margin-left: auto;
      }

      .preview-status-item {
        display: flex;
        align-items: center;
        gap: 5px;
        font-family: 'Consolas', 'Monaco', monospace;
        white-space: nowrap;
        flex-shrink: 0;
      }

      .preview-status-item label {
        display: flex;
        align-items: center;
        gap: 4px;
        cursor: pointer;
        font-family: inherit;
        font-size: inherit;
        color: var(--secondary-color);
      }

      .preview-status-item input[type="checkbox"] {
        width: 14px;
        height: 14px;
        cursor: pointer;
        margin: 0;
      }

      .preview-status-item span {
        color: var(--secondary-color);
      }

      .fullscreen-toggle {
        background: none;
        border: none;
        color: var(--text-color);
        cursor: pointer;
        padding: 2px 8px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s ease;
        font-size: 12px;
      }

      .fullscreen-toggle:hover {
        background: var(--hover-color);
      }

      /* Markdown 内容样式 */
      .preview-container > *:first-child {
        margin-top: 0;
      }

      .preview-container > *:last-child {
        margin-bottom: 0;
      }

      .preview-container h1,
      .preview-container h2,
      .preview-container h3,
      .preview-container h4,
      .preview-container h5,
      .preview-container h6 {
        margin-top: 1.8em;
        margin-bottom: 0.8em;
        line-height: 1.2;
        color: var(--text-color);
      }

      .preview-container h1:first-child,
      .preview-container h2:first-child,
      .preview-container h3:first-child,
      .preview-container h4:first-child,
      .preview-container h5:first-child,
      .preview-container h6:first-child {
        margin-top: 0;
      }

      .preview-container p {
        margin: 1.2em 0;
        line-height: 1.8;
      }

      .preview-container a {
        display: inline;
        color: var(--link-color);
        text-decoration: none;
        border-bottom: 1px solid transparent;
        transition: all 0.2s ease;
        padding: 2px 4px;
        margin: 0 -4px;
        border-radius: 4px;
        text-align: left;
      }

      /* 处理单独一行的链接 */
      .preview-container p > a:only-child {
        display: inline-block;
        text-align: left;
        width: auto;
      }

      /* 确保链接在段落中的对齐方式 */
      .preview-container p {
        text-align: left;
      }

      .preview-container a:hover {
        background: var(--hover-color);
        color: var(--link-hover-color);
        border-bottom-color: var(--link-hover-color);
      }

      .preview-container a:visited {
        color: var(--link-visited-color);
      }

      .preview-container a:visited:hover {
        background: var(--hover-color);
        border-bottom-color: var(--link-visited-color);
      }

      .preview-container a[href^="http"]::after {
        content: "↗";
        display: inline;
        margin-left: 2px;
        font-size: 0.9em;
        opacity: 0.6;
      }
      .preview-container ul,
      .preview-container ol {
        margin: 1em 0;
        padding-left: 1.5em;
      }

      .preview-container li {
        margin: 0.5em 0;
      }

      .preview-container blockquote {
        margin: 1.2em 0;
        padding: 1em 1.2em;
        border-left: 4px solid var(--border-color);
        background: var(--bg-color);
        border-radius: 0 4px 4px 0;
        display: flow-root;
        width: fit-content;
        max-width: 100%;
        box-shadow: 0 2px 4px var(--shadow-color);
        transition: all 0.2s ease;
      }

      .preview-container blockquote > *:first-child {
        margin-top: 0;
      }

      .preview-container blockquote > *:last-child {
        margin-bottom: 0;
      }

      .preview-container blockquote p {
        margin: 0.8em 0;
        line-height: 1.6;
      }

      .preview-container blockquote + blockquote {
        margin-top: -0.5em;
      }

      /* 嵌套引用的样式 */
      .preview-container blockquote blockquote {
        margin: 0.8em 0;
        border-left-color: var(--secondary-color);
        background: var(--editor-bg);
        box-shadow: none;
      }

      /* 移动端适配 */
      @media (max-width: 768px) {
        .preview-container blockquote {
          padding: 0.8em 1em;
          margin: 1em 0;
          width: 100%;
        }
      }

      /* 代码块基础样式 */
      .preview-container pre {
        background: var(--editor-bg);
        padding: 1.2em 1em;
        border-radius: 8px;
        overflow: auto;
        position: relative;
        margin: 1.5em 0;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        line-height: 1.5;
        font-size: 0.95em;
        border: 1px solid var(--border-color);
        scrollbar-width: thin;
        scrollbar-color: var(--secondary-color) transparent;
      }

      /* 行内代码样式 */
      .preview-container code {
        background: var(--editor-bg);
        padding: 0.2em 0.4em;
        margin: 0 0.2em;
        border-radius: 4px;
        font-size: 0.9em;
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        border: 1px solid var(--border-color);
      }

      /* 代码块中的代码样式 */
      .preview-container pre code {
        background: none;
        padding: 0;
        margin: 0;
        font-size: 0.95em;
        white-space: pre;
        word-break: normal;
        word-wrap: normal;
        line-height: inherit;
        tab-size: 2;
        hyphens: none;
        border: none;
      }

      /* 代码块滚动条样式 */
      .preview-container pre::-webkit-scrollbar {
        width: 6px;
        height: 6px;
      }

      .preview-container pre::-webkit-scrollbar-track {
        background: transparent;
      }

      .preview-container pre::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 3px;
        border: 2px solid var(--editor-bg);
      }

      .preview-container pre::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      /* 代码块语言标签 */
      .preview-container pre::before {
        content: attr(data-language);
        position: absolute;
        top: 0.5em;
        right: 0.5em;
        font-size: 0.85em;
        color: var(--secondary-color);
        padding: 0.2em 0.5em;
        border-radius: 3px;
        background: var(--container-bg);
        opacity: 0.8;
        transition: opacity 0.2s ease;
      }

      .preview-container pre:hover::before {
        opacity: 1;
      }

      /* 代码高亮主题 - 浅色模式 */
      .hljs {
        color: #383a42;
        background: var(--editor-bg);
      }

      .hljs-comment,
      .hljs-quote {
        color: #a0a1a7;
        font-style: italic;
      }

      .hljs-doctag,
      .hljs-keyword,
      .hljs-formula {
        color: #a626a4;
      }

      .hljs-section,
      .hljs-name,
      .hljs-selector-tag,
      .hljs-deletion,
      .hljs-subst {
        color: #e45649;
      }

      .hljs-literal {
        color: #0184bb;
      }

      .hljs-string,
      .hljs-regexp,
      .hljs-addition,
      .hljs-attribute,
      .hljs-meta .hljs-string {
        color: #50a14f;
      }

      .hljs-attr,
      .hljs-variable,
      .hljs-template-variable,
      .hljs-type,
      .hljs-selector-class,
      .hljs-selector-attr,
      .hljs-selector-pseudo,
      .hljs-number {
        color: #986801;
      }

      .hljs-symbol,
      .hljs-bullet,
      .hljs-link,
      .hljs-meta,
      .hljs-selector-id,
      .hljs-title {
        color: #4078f2;
      }

      .hljs-built_in,
      .hljs-title.class_,
      .hljs-class .hljs-title {
        color: #c18401;
      }

      .hljs-emphasis {
        font-style: italic;
      }

      .hljs-strong {
        font-weight: bold;
      }

      /* 代码高亮主题 - 深色模式 */
      [data-theme="dark"] .hljs {
        color: #abb2bf;
        background: var(--editor-bg);
      }

      [data-theme="dark"] .hljs-comment,
      [data-theme="dark"] .hljs-quote {
        color: #7f848e;
        font-style: italic;
      }

      [data-theme="dark"] .hljs-doctag,
      [data-theme="dark"] .hljs-keyword,
      [data-theme="dark"] .hljs-formula {
        color: #c678dd;
      }

      [data-theme="dark"] .hljs-section,
      [data-theme="dark"] .hljs-name,
      [data-theme="dark"] .hljs-selector-tag,
      [data-theme="dark"] .hljs-deletion,
      [data-theme="dark"] .hljs-subst {
        color: #e06c75;
      }

      [data-theme="dark"] .hljs-literal {
        color: #56b6c2;
      }

      [data-theme="dark"] .hljs-string,
      [data-theme="dark"] .hljs-regexp,
      [data-theme="dark"] .hljs-addition,
      [data-theme="dark"] .hljs-attribute,
      [data-theme="dark"] .hljs-meta .hljs-string {
        color: #98c379;
      }

      [data-theme="dark"] .hljs-attr,
      [data-theme="dark"] .hljs-variable,
      [data-theme="dark"] .hljs-template-variable,
      [data-theme="dark"] .hljs-type,
      [data-theme="dark"] .hljs-selector-class,
      [data-theme="dark"] .hljs-selector-attr,
      [data-theme="dark"] .hljs-selector-pseudo,
      [data-theme="dark"] .hljs-number {
        color: #d19a66;
      }

      [data-theme="dark"] .hljs-symbol,
      [data-theme="dark"] .hljs-bullet,
      [data-theme="dark"] .hljs-link,
      [data-theme="dark"] .hljs-meta,
      [data-theme="dark"] .hljs-selector-id,
      [data-theme="dark"] .hljs-title {
        color: #61afef;
      }

      [data-theme="dark"] .hljs-built_in,
      [data-theme="dark"] .hljs-title.class_,
      [data-theme="dark"] .hljs-class .hljs-title {
        color: #e6c07b;
      }

      [data-theme="dark"] .hljs-emphasis {
        font-style: italic;
      }

      [data-theme="dark"] .hljs-strong {
        font-weight: bold;
      }

      /* 代码复制按钮 */
      .copy-button {
        position: absolute;
        top: 0.5em;
        right: 0.5em;
        padding: 0.2em 0.5em;
        font-size: 0.85em;
        color: var(--text-color);
        background: var(--container-bg);
        border: 1px solid var(--border-color);
        border-radius: 3px;
        cursor: pointer;
        opacity: 0;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 4px;
      }

      .preview-container pre:hover .copy-button {
        opacity: 0.8;
      }

      .copy-button:hover {
        opacity: 1 !important;
        background: var(--hover-color);
      }

      .copy-button.copied {
        color: #4caf50;
        border-color: #4caf50;
        opacity: 1;
      }

      /* 移动端适配 */
      @media (max-width: 768px) {
        .preview-container pre {
          padding: 1em 0.8em;
          font-size: 0.9em;
        }

        .preview-container code {
          font-size: 0.85em;
        }

        .preview-container pre::before {
          opacity: 1;
        }
      }

      /* 代码块中的链接样式 */
      .preview-container pre a,
      .preview-container code a {
        border-bottom: none;
      }

      .preview-container pre a::after,
      .preview-container code a::after {
        display: none;
      }

      /* 图片链接样式 */
      .preview-container a:has(img) {
        border-bottom: none;
      }

      .preview-container a:has(img)::after {
        display: none;
      }

      .preview-container hr {
        margin: 2em 0;
        border: none;
        border-top: 1px solid var(--border-color);
      }

      .preview-container table {
        width: 100%;
        border-collapse: collapse;
        margin: 1.5em 0;
        overflow-x: auto;
        display: block;
      }

      .preview-container th,
      .preview-container td {
        border: 1px solid var(--border-color);
        padding: 8px 12px;
        text-align: left;
      }

      .preview-container th {
        background-color: var(--hover-color);
        font-weight: 600;
      }

      .preview-container tr:nth-child(even) {
        background-color: var(--editor-bg);
      }

      .preview-container tr:hover {
        background-color: var(--hover-color);
      }

      .preview-container img {
        max-width: 100%;
        margin: 1em 0;
        border-radius: 4px;
      }

      /* 滚动条样式 */
      .editor-container textarea,
      .preview-container,
      .preview-content {
        scrollbar-width: thin;
        scrollbar-color: var(--secondary-color) transparent;
      }

      .editor-container textarea::-webkit-scrollbar,
      .preview-container::-webkit-scrollbar,
      .preview-content::-webkit-scrollbar {
        width: 8px;
        height: 8px;
      }

      .editor-container textarea::-webkit-scrollbar-track,
      .preview-container::-webkit-scrollbar-track,
      .preview-content::-webkit-scrollbar-track {
        background: transparent;
      }

      .editor-container textarea::-webkit-scrollbar-thumb,
      .preview-container::-webkit-scrollbar-thumb,
      .preview-content::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 4px;
        border: 2px solid var(--editor-bg);
      }

      .editor-container textarea::-webkit-scrollbar-thumb:hover,
      .preview-container::-webkit-scrollbar-thumb:hover,
      .preview-content::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      /* 移动端滚动条优化 */
      @media (max-width: 768px) {
        .editor-container textarea::-webkit-scrollbar,
        .preview-container::-webkit-scrollbar,
        .preview-content::-webkit-scrollbar {
          width: 6px;
          height: 6px;
        }

        .editor-container textarea::-webkit-scrollbar-thumb,
        .preview-container::-webkit-scrollbar-thumb,
        .preview-content::-webkit-scrollbar-thumb {
          border-width: 1.5px;
        }
      }

      /* 移动端响应式布局优化 */
      @media (max-width: 768px) {
        .container {
          padding: 5px;
          height: 100vh;
          max-height: -webkit-fill-available;
          display: flex;
          flex-direction: column;
          width: 100%;
        }

        .container.toolbar-hidden {
          padding: 5px;
        }

        .editor-container {
          flex: 1;
          min-height: 0;
          gap: 5px;
          margin-bottom: env(safe-area-inset-bottom, 15px);
          width: 100%;
          display: flex;
          flex-direction: column;
        }

        .editor-container.preview-mode {
          display: flex;
          flex-direction: column;
          height: calc(100vh - 60px - env(safe-area-inset-bottom, 15px)); /* 减去工具栏和底部安全区域 */
        }

        .editor-wrapper,
        .preview-container {
          flex: 1;
          min-height: 0;
          overflow: auto;
          -webkit-overflow-scrolling: touch;
          width: 100%;
        }

        .editor-container.preview-mode .editor-wrapper,
        .editor-container.preview-mode .preview-container {
          flex: 1;
          height: 0; /* 让flex:1生效 */
          min-height: 0;
          max-height: none;
          width: 100%;
        }

        /* 处理键盘弹出时的布局 */
        @supports (-webkit-touch-callout: none) {
          .editor-container.preview-mode {
            height: calc(100vh - 60px - env(safe-area-inset-bottom, 15px) - env(keyboard-inset-height, 0px));
          }
        }

        /* 确保内容可滚动 */
        .editor-container.preview-mode .editor-wrapper textarea,
        .editor-container.preview-mode .preview-container {
          height: 100%;
          overflow-y: auto;
        }
      }

      /* 处理超小屏幕设备 */
      @media (max-width: 320px) {
        .container {
          padding: 3px 3px 12px 3px;
        }

        .container.toolbar-hidden {
          padding: 8px;
        }

        .editor-wrapper textarea,
        .line-numbers span {
          font-size: 15px;
        }

        .preview-container {
          font-size: 15px;
          padding: 10px 10px 20px 10px;
        }
      }

      /* 处理横屏模式 */
      @media (max-height: 480px) and (orientation: landscape) {
        .container {
          padding: 5px;
          width: 100%;
        }
        
        .container.toolbar-hidden {
          padding: 5px;
        }
        
        .toolbar {
          padding: 6px 10px;
          margin-bottom: 8px;
          width: 100%;
        }
        
        .editor-container {
          height: calc(100vh - 80px);
          width: 100%;
        }
        
        .editor-container.preview-mode {
          grid-template-columns: 1fr 1fr; /* 横屏时恢复左右布局 */
          gap: 8px;
          width: 100%;
        }
        
        .editor-wrapper,
        .preview-container {
          width: 100%;
          height: 100%;
          box-sizing: border-box;
        }

        .editor-wrapper textarea,
        .preview-container {
          width: 100%;
          height: 100%;
          box-sizing: border-box;
        }
        
        .editor-container.preview-mode .editor-wrapper,
        .editor-container.preview-mode .preview-container {
          height: 100%;
          width: 100%;
        }

        /* 横屏模式下状态栏优化 */
        .status-bar,
        .preview-status-bar {
          height: 24px;
          font-size: 11px;
          padding: 0 6px;
          width: 100%;
        }

        .status-bar .status-left,
        .status-bar .status-right,
        .preview-status-bar .preview-status-left,
        .preview-status-bar .preview-status-right {
          gap: 8px;
        }

        .status-bar .status-right,
        .preview-status-bar .preview-status-right {
          padding-left: 8px;
        }

        .status-item,
        .preview-status-item {
          margin-right: 8px;
        }

        .status-item label,
        .preview-status-item label {
          gap: 2px;
        }

        .status-item input[type="checkbox"],
        .preview-status-item input[type="checkbox"] {
          width: 12px;
          height: 12px;
        }

        /* 调整状态栏右侧开关的间距 */
        .status-right .status-item {
          margin-right: 4px;
        }

        .status-right .switch-label,
        .preview-status-right .switch-label {
          font-size: 11px;
          padding: 2px 4px;
        }
      }
      
      /* 适配折叠屏设备 */
      @media (max-width: 350px) and (min-height: 600px) {
        .container {
          padding: 4px;
        }
        
        .toolbar {
          flex-direction: column;
          align-items: stretch;
        }
        
        .toolbar-left,
        .toolbar-right {
          justify-content: center;
        }
        
        .editor-container {
          height: calc(100vh - 140px);
        }
      }
      
      /* 适配深色模式和高对比度显示 */
      @media (prefers-contrast: high) {
        :root {
          --border-color: #666666;
          --shadow-color: rgba(0, 0, 0, 0.3);
        }
        
        .editor-container textarea,
        .preview-container {
          border-width: 2px;
        }
      }

      /* 适配强制颜色模式 */
      @media (forced-colors: active) {
        :root {
          --border-color: CanvasText;
          --text-color: CanvasText;
          --bg-color: Canvas;
          --primary-color: LinkText;
          --secondary-color: GrayText;
          --container-bg: Canvas;
          --editor-bg: Canvas;
          --hover-color: Highlight;
          --link-color: LinkText;
          --link-hover-color: LinkText;
          --link-visited-color: VisitedText;
        }

        .editor-container textarea,
        .preview-container,
        .toolbar,
        .status-bar,
        .preview-status-bar {
          border: 1px solid CanvasText;
        }

        .markdown-toolbar button,
        .toolbar-select,
        .fullscreen-toggle {
          border: 1px solid CanvasText;
          background: Canvas;
          color: CanvasText;
        }

        .markdown-toolbar button:hover,
        .toolbar-select:hover,
        .fullscreen-toggle:hover {
          background: Highlight;
          color: HighlightText;
        }
      }
      
      /* 减少动画以适应省电模式 */
      @media (prefers-reduced-motion: reduce) {
        * {
          transition: none !important;
        }
      }

      /* 工具栏样式 */
      .markdown-toolbar {
        display: flex;
        gap: 4px;
        align-items: center;
      }

      .markdown-toolbar button {
        padding: 4px 8px;
        background: var(--editor-bg);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        color: var(--text-color);
        cursor: pointer;
        font-size: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        min-width: 28px;
        height: 28px;
        transition: all 0.2s ease;
      }

      .markdown-toolbar button:hover {
        background: var(--hover-color);
      }

      .toolbar-select {
        padding: 4px 8px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background: var(--editor-bg);
        color: var(--text-color);
        font-size: 14px;
        cursor: pointer;
      }

      .toolbar-select:hover {
        background: var(--hover-color);
      }

      /* Emoji 选择器样式 */
      .emoji-picker {
        position: fixed; /* 改为fixed定位，避免滚动问题 */
        left: 50%;
        top: 50%;
        transform: translate(-50%, -50%);
        background: var(--container-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        box-shadow: 0 2px 8px var(--shadow-color);
        padding: 15px;
        display: none;
        z-index: 1000;
        max-height: 80vh;
        width: 90%;
        max-width: 400px;
        overflow-y: auto;
        -webkit-overflow-scrolling: touch;
      }

      .emoji-picker-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(40px, 1fr));
        gap: 8px;
      }

      .emoji-picker button {
        width: 40px;
        height: 40px;
        padding: 8px;
        border: none;
        background: none;
        cursor: pointer;
        border-radius: 8px;
        transition: all 0.2s ease;
        font-size: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .emoji-picker button:hover {
        background: var(--hover-color);
      }

      .emoji-picker-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        z-index: 999;
        display: none;
      }

      /* 全屏模式样式 */
      .preview-container.fullscreen {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        width: 100vw;
        height: 100vh;
        z-index: 9999;
        border-radius: 0;
        border: none;
      }

      /* 真实全屏模式的样式 */
      .preview-container:fullscreen {
        background-color: var(--container-bg);
        width: 100vw;
        height: 100vh;
        padding: 0;
        margin: 0;
        border: none;
        border-radius: 0;
      }

      .preview-container:fullscreen .preview-content {
        height: calc(100vh - 25px);
        padding: 20px;
        max-width: 1200px;
        margin: 0 auto;
      }

      .preview-container:fullscreen .preview-status-bar {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        background: var(--editor-bg);
        border-top: 1px solid var(--border-color);
      }

      /* 移动端全屏适配 */
      @media (max-width: 768px) {
        .preview-container:fullscreen .preview-content {
          padding: 15px;
          height: calc(100vh - 25px - env(safe-area-inset-bottom, 0px));
        }
        
        .preview-container:fullscreen .preview-status-bar {
          padding-bottom: env(safe-area-inset-bottom, 0px);
        }
      }

      .preview-container.fullscreen .preview-content {
        height: calc(100vh - 25px);
        padding: 20px;
      }

      /* 全屏切换按钮样式 */
      .fullscreen-toggle {
        background: none;
        border: none;
        color: var(--text-color);
        cursor: pointer;
        padding: 2px 8px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s ease;
        font-size: 12px;
      }

      .fullscreen-toggle:hover {
        background: var(--hover-color);
      }

      .fullscreen-toggle .fullscreen-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 16px;
        height: 16px;
      }

      /* 预览区双击时禁止选中文本 */
      .preview-container.fullscreen .preview-content {
        -webkit-user-select: none;
        -moz-user-select: none;
        -ms-user-select: none;
        user-select: none;
      }

      /* 预览区恢复正常文本选择 */
      .preview-container:not(.fullscreen) .preview-content {
        -webkit-user-select: text;
        -moz-user-select: text;
        -ms-user-select: text;
        user-select: text;
      }

      /* 全屏模式下的状态栏样式 */
      .preview-container.fullscreen .preview-status-bar {
        position: fixed;
        bottom: env(safe-area-inset-bottom, 0);
        left: 0;
        right: 0;
        background: var(--editor-bg);
        border-top: 1px solid var(--border-color);
        z-index: 10000;
      }

      /* 响应式布局 - 移动端优化 */
      @media (max-width: 768px) {
        .toolbar {
          padding: 8px;
          margin-bottom: 12px;
          white-space: nowrap;
          gap: 8px;
        }

        .toolbar-left,
        .toolbar-right {
          gap: 8px;
        }

        .markdown-toolbar button {
          min-width: 32px;
          height: 32px;
          padding: 4px;
        }

        .toolbar-select {
          padding: 4px;
          font-size: 13px;
        }

        .note-name {
          font-size: 0.9rem;
          padding: 4px 8px;
        }

        .emoji-picker {
          padding: 10px;
        }

        .emoji-picker button {
          width: 36px;
          height: 36px;
          font-size: 18px;
        }
      }

      /* 移动端状态栏适配 */
      @media (max-width: 768px) {
        .preview-status-bar {
          padding: 0 8px;
          overflow: hidden;
        }

        .preview-status-right {
          gap: 8px;
        }

        .preview-status-item {
          margin-left: 8px;
          font-size: 11px;
        }
      }

      /* 处理超小屏幕设备状态栏 */
      @media (max-width: 320px) {
        .preview-status-bar {
          padding: 0 5px;
        }

        .preview-status-item {
          margin-left: 5px;
          font-size: 10px;
        }
      }

      /* 全屏模式下的移动端优化 */
      @media (max-width: 768px) {
        .preview-container.fullscreen {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          width: 100vw;
          height: 100vh;
          height: -webkit-fill-available;
          z-index: 9999;
          border-radius: 0;
          padding-bottom: env(safe-area-inset-bottom, 0);
        }

        .preview-container.fullscreen .preview-content {
          height: calc(100vh - 25px - env(safe-area-inset-bottom, 0));
          padding: 15px;
        }
      }

      /* 处理横屏模式 */
      @media (max-height: 480px) and (orientation: landscape) {
        .preview-container.fullscreen .preview-status-bar {
          height: 24px;
          font-size: 11px;
          padding: 0 6px;
        }

        .preview-container.fullscreen .preview-content {
          height: calc(100vh - 24px);
          padding: 10px;
        }
      }

      /* 在现有样式的末尾添加密码相关样式 */
      .password-dialog {
        display: none;
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: var(--container-bg);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 8px 24px var(--shadow-color);
        z-index: 1000;
        width: 90%;
        max-width: 360px;
        transition: all 0.3s ease;
      }

      .password-dialog h3 {
        margin: 0 0 20px 0;
        color: var(--text-color);
        font-size: 1.2em;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .password-dialog h3::before {
        content: '🔒';
        font-size: 1.1em;
      }

      .password-dialog input[type="password"] {
        width: 100%;
        padding: 10px 14px;
        margin-bottom: 12px;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        background: var(--editor-bg);
        color: var(--text-color);
        font-size: 15px;
        transition: all 0.2s ease;
      }

      .password-dialog input[type="password"]:hover {
        border-color: var(--secondary-color);
      }

      .password-dialog input[type="password"]:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px var(--primary-color-alpha);
      }

      .password-dialog-message {
        margin-bottom: 20px;
        font-size: 0.95em;
        color: #e74c3c;
        min-height: 20px;
        transition: all 0.3s ease;
        opacity: 0;
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .password-dialog-message::before {
        content: '⚠️';
        font-size: 1.1em;
      }

      .password-dialog-message.success {
        color: #2ecc71;
      }

      .password-dialog-message.success::before {
        content: '✅';
      }

      .password-dialog-message.show {
        opacity: 1;
      }

      .password-dialog-buttons {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
      }

      .password-dialog button {
        padding: 8px 16px;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        background: var(--editor-bg);
        color: var(--text-color);
        cursor: pointer;
        font-size: 14px;
        font-weight: 500;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .password-dialog button:hover {
        background: var(--hover-color);
        border-color: var(--secondary-color);
      }

      .password-dialog button.primary {
        background: var(--primary-color);
        color: white;
        border-color: var(--primary-color);
      }

      .password-dialog button.primary:hover {
        opacity: 0.9;
        transform: translateY(-1px);
      }

      .password-dialog button:active {
        transform: translateY(1px);
      }

      .password-dialog-overlay {
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(4px);
        z-index: 999;
        transition: all 0.3s ease;
      }

      .password-protected .editor-container,
      .password-protected .toolbar {
        filter: blur(8px);
        pointer-events: none;
        user-select: none;
      }

      .password-status {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--text-color);
        font-size: 0.9rem;
        padding: 4px 8px;
        border-radius: 6px;
        cursor: pointer;
        transition: all 0.2s ease;
      }

      .password-status:hover {
        background: var(--hover-color);
      }

      .password-status-icon {
        font-size: 1.2rem;
        transition: transform 0.3s ease;
      }

      .password-status:hover .password-status-icon {
        transform: scale(1.1);
      }

      @media (max-width: 768px) {
        .password-dialog {
          width: 90%;
          padding: 20px;
          /* 保持在屏幕中间 */
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          margin: 0;
        }

        .password-dialog h3 {
          font-size: 1.1em;
        }

        .password-dialog input[type="password"] {
          font-size: 14px;
          padding: 8px 12px;
        }

        .password-dialog button {
          padding: 7px 14px;
        }
      }

      @media (max-width: 480px) {
        .password-dialog {
          width: 100%;
          max-width: none;
          border-radius: 12px 12px 0 0;
          bottom: 0;
          top: auto;
          transform: translateX(-50%);
          padding-bottom: calc(20px + env(safe-area-inset-bottom));
        }
      }

      /* 工具栏右侧按钮样式 */
      .toolbar-right {
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .toolbar-button {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--text-color);
        font-size: 0.9rem;
        padding: 4px 8px;
        border-radius: 6px;
        cursor: pointer;
        transition: all 0.2s ease;
        border: none;
        background: none;
      }

      .toolbar-button:hover {
        background: var(--hover-color);
      }

      .toolbar-button .icon {
        font-size: 1.2rem;
        transition: transform 0.3s ease;
      }

      .toolbar-button:hover .icon {
        transform: scale(1.1);
      }

      .toolbar-button .label {
        display: none;
      }

      @media (min-width: 768px) {
        .toolbar-button {
          padding: 6px 12px;
        }

        .toolbar-button .label {
          display: inline;
        }
      }

      /* 主题切换按钮特定样式 */
      .theme-toggle .sun-icon,
      .theme-toggle .moon-icon {
        display: none;
      }

      [data-theme="dark"] .moon-icon {
        display: block;
      }

      [data-theme="light"] .sun-icon {
        display: block;
      }

      /* 密码状态按钮特定样式 */
      .password-status {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--text-color);
        font-size: 0.9rem;
        padding: 4px 8px;
        border-radius: 6px;
        cursor: pointer;
        transition: all 0.2s ease;
      }

      .password-status:hover {
        background: var(--hover-color);
      }

      .password-status .icon {
        font-size: 1.2rem;
        transition: transform 0.3s ease;
      }

      .password-status:hover .icon {
        transform: scale(1.1);
      }

      /* 添加 Toast 提示框样式 */
      .toast-container {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 10px;
        pointer-events: none;
        /* 保持在右上角 */
        top: 20px;
        right: 20px;
        width: auto;
        max-width: calc(100% - 40px);
        transform: none;
      }

      .toast {
        background: var(--container-bg);
        color: var(--text-color);
        padding: 12px 24px;
        border-radius: 8px;
        box-shadow: 0 4px 12px var(--shadow-color);
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 8px;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.3s ease;
        border: 1px solid var(--border-color);
        pointer-events: all;
        max-width: 300px;
        word-break: break-word;
      }

      .toast.show {
        opacity: 1;
        transform: translateX(0);
      }

      .toast.success {
        border-left: 4px solid #4caf50;
      }

      .toast.error {
        border-left: 4px solid #f44336;
      }

      .toast.info {
        border-left: 4px solid #2196f3;
      }

      .toast.warning {
        border-left: 4px solid #ff9800;
      }

      .toast-icon {
        font-size: 18px;
        flex-shrink: 0;
      }

      .toast-message {
        flex: 1;
        margin-right: 8px;
      }

      .toast-close {
        cursor: pointer;
        opacity: 0.7;
        transition: opacity 0.2s ease;
        padding: 4px;
        margin: -4px;
        border-radius: 4px;
      }

      .toast-close:hover {
        opacity: 1;
        background: var(--hover-color);
      }

      @media (max-width: 768px) {
        .toast-container {
          /* 保持在右上角 */
          top: 20px;
          right: 20px;
          width: auto;
          max-width: calc(100% - 40px);
          transform: none;
        }

        .toast {
          width: 100%;
          transform: translateY(100%);
        }

        .toast.show {
          transform: translateY(0);
        }
      }

      /* 添加复制全部按钮样式 */
      .copy-all-button {
        background: none;
        border: none;
        color: var(--text-color);
        cursor: pointer;
        padding: 0px 4px;
        border-radius: 4px;
        font-size: 12px;
        display: flex;
        align-items: center;
        gap: 4px;
        transition: all 0.2s ease;
      }

      .copy-all-button:hover {
        background: var(--hover-color);
      }

      /* 添加复制全部的动效样式 */
      .copy-all-item {
        cursor: pointer;
        transition: all 0.2s ease;
        padding: 0px 4px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        gap: 4px;
      }

      .copy-all-item:hover {
        background: var(--hover-color);
      }

      .copy-all-item .copy-icon {
        transition: transform 0.2s ease;
      }

      .copy-all-item:hover .copy-icon {
        transform: scale(1.1);
      }

      .copy-all-item.copied {
        animation: copied-animation 0.5s ease;
      }

      @keyframes copied-animation {
        0% { transform: scale(1); }
        50% { transform: scale(1.1); }
        100% { transform: scale(1); }
      }

      /* 表格样式 */
      .content table {
        width: 100%;
        border-collapse: collapse;
        margin: 1.5em 0;
        overflow-x: auto;
        display: block;
      }

      .content th,
      .content td {
        border: 1px solid var(--border-color);
        padding: 8px 12px;
        text-align: left;
      }

      .content th {
        background-color: var(--hover-color);
        font-weight: 600;
      }

      .content tr:nth-child(even) {
        background-color: var(--editor-bg);
      }

      .content tr:hover {
        background-color: var(--hover-color);
      }

      /* 移动端表格适配 */
      @media (max-width: 768px) {
        .content table {
          font-size: 14px;
        }

        .content th,
        .content td {
          padding: 6px 8px;
        }
      }

      /* 表格滚动条样式 */
      .content table::-webkit-scrollbar {
        height: 8px;
        width: 8px;
      }

      .content table::-webkit-scrollbar-track {
        background: transparent;
      }

      .content table::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 4px;
        border: 2px solid var(--editor-bg);
      }

      .content table::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      /* 表格滚动条样式 */
      .content table::-webkit-scrollbar {
        height: 8px;
        width: 8px;
      }

      .content table::-webkit-scrollbar-track {
        background: transparent;
      }

      .content table::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 4px;
        border: 2px solid var(--editor-bg);
      }

      .content table::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      /* 图片样式 */
      .content img {
        max-width: 100%;
        height: auto;
        margin: 1em 0;
        border-radius: 8px;
        display: block;
        box-shadow: 0 2px 8px var(--shadow-color);
        transition: all 0.3s ease;
        opacity: 0;
        animation: fadeIn 0.5s ease forwards;
      }

      /* 图片容器 */
      .content p:has(img) {
        text-align: center;
        margin: 2em 0;
      }

      /* 图片悬停效果 */
      .content img:hover {
        transform: scale(1.01);
        box-shadow: 0 4px 12px var(--shadow-color);
      }

      /* 图片标题样式 */
      .content img + em {
        display: block;
        text-align: center;
        color: var(--secondary-color);
        font-size: 0.9em;
        margin-top: 0.5em;
      }

      /* 移动端图片适配 */
      @media (max-width: 768px) {
        .content img {
          border-radius: 6px;
          margin: 0.8em 0;
        }

        .content p:has(img) {
          margin: 1.5em 0;
        }

        /* 禁用移动端图片缩放动画 */
        .content img:hover {
          transform: none;
          box-shadow: 0 2px 8px var(--shadow-color);
        }
      }

      /* 图片加载动画 */
      @keyframes fadeIn {
        from {
          opacity: 0;
          transform: translateY(10px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }

      /* 图片加载失败样式 */
      .content img:not([src]),
      .content img[src=""],
      .content img[src*="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="] {
        position: relative;
        min-height: 100px;
        background: var(--editor-bg);
        border: 1px dashed var(--border-color);
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .content img:not([src])::after,
      .content img[src=""]::after,
      .content img[src*="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="]::after {
        content: "图片加载失败";
        position: absolute;
        color: var(--secondary-color);
        font-size: 0.9em;
      }

      /* 大图查看模式 */
      .content img.enlarged {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        max-width: 90vw;
        max-height: 90vh;
        object-fit: contain;
        z-index: 1000;
        cursor: zoom-out;
        margin: 0;
        padding: 0;
        background: var(--bg-color);
        box-shadow: 0 0 20px var(--shadow-color);
      }

      /* 大图查看遮罩层 */
      .image-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.8);
        z-index: 999;
        display: none;
        opacity: 0;
        transition: opacity 0.3s ease;
      }

      .image-overlay.active {
        display: block;
        opacity: 1;
      }

      /* 代码块复制按钮样式 */
      .content pre {
        position: relative;
      }

      .copy-button {
        position: absolute;
        top: 0.5em;
        right: 0.5em;
        padding: 0.2em 0.5em;
        font-size: 0.85em;
        color: var(--text-color);
        background: var(--container-bg);
        border: 1px solid var(--border-color);
        border-radius: 3px;
        cursor: pointer;
        opacity: 0;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 4px;
        z-index: 2;
      }

      .content pre:hover .copy-button {
        opacity: 0.8;
      }

      .copy-button:hover {
        opacity: 1 !important;
        background: var(--hover-color);
        transform: translateY(-1px);
      }

      .copy-button.copied {
        color: #4caf50;
        border-color: #4caf50;
        opacity: 1;
      }

      .copy-button.error {
        color: #f44336;
        border-color: #f44336;
        opacity: 1;
      }

      /* 代码块语言标签 */
      .content pre::before {
        content: attr(data-language);
        position: absolute;
        top: 0;
        right: 0;
        padding: 0.2em 0.5em;
        font-size: 0.85em;
        background: var(--container-bg);
        border-bottom-left-radius: 4px;
        color: var(--secondary-color);
        opacity: 0.8;
        transition: opacity 0.2s ease;
      }

      .content pre:hover::before {
        opacity: 0;
      }

      @media (max-width: 768px) {
        .copy-button {
          padding: 0.15em 0.4em;
          font-size: 0.8em;
        }

        .content pre::before {
          font-size: 0.8em;
          padding: 0.15em 0.4em;
        }
      }

      .info-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px;
        background: var(--editor-bg);
        border-radius: 12px;
        margin-bottom: 20px;
        font-size: 14px;
        border: 1px solid var(--border-color);
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
        gap: 15px;
        min-width: 0;
      }

      .info-bar::-webkit-scrollbar {
        height: 6px;
        width: 6px;
      }

      .info-bar::-webkit-scrollbar-track {
        background: transparent;
      }

      .info-bar::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 3px;
      }

      .info-bar::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      .info-left {
        display: flex;
        gap: 15px;
        flex-shrink: 0;
        margin-right: auto;
      }

      .info-right {
        display: flex;
        align-items: center;
        gap: 15px;
        flex-shrink: 0;
        margin-left: auto;
      }

      .info-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 4px 10px;
        border-radius: 6px;
        transition: all 0.2s ease;
        white-space: nowrap;
        flex-shrink: 0;
      }

      .info-item:hover {
        background: var(--hover-color);
      }

      .theme-toggle {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 4px 10px;
        border-radius: 6px;
        border: none;
        color: var(--text-color);
        cursor: pointer;
        font-size: 14px;
        transition: all 0.2s ease;
        background: transparent;
        white-space: nowrap;
        flex-shrink: 0;
      }

      .theme-toggle:hover {
        background: var(--hover-color);
      }

      .theme-toggle:active {
        transform: scale(0.95);
      }

      .theme-toggle .sun-icon,
      .theme-toggle .moon-icon {
        display: none;
        font-size: 1.2rem;
      }

      .theme-toggle .label {
        font-size: 14px;
      }

      [data-theme="dark"] .moon-icon {
        display: block;
      }

      [data-theme="light"] .sun-icon {
        display: block;
      }

      @media (max-width: 768px) {
        .theme-toggle {
          padding: 4px 8px;
        }

        .theme-toggle .label {
          font-size: 13px;
        }
      }

      @media (max-width: 768px) {
        .info-bar {
          padding: 10px;
          gap: 10px;
        }

        .info-left,
        .info-right {
          gap: 10px;
        }

        .info-item {
          padding: 4px 8px;
          font-size: 13px;
        }
      }

      /* 添加KaTeX相关样式 */
      .katex-display {
        overflow-x: auto;
        overflow-y: hidden;
        padding: 1em 0;
        margin: 1em 0;
      }

      .katex-display::-webkit-scrollbar {
        height: 6px;
      }

      .katex-display::-webkit-scrollbar-track {
        background: transparent;
      }

      .katex-display::-webkit-scrollbar-thumb {
        background-color: var(--secondary-color);
        border-radius: 3px;
      }

      .katex-display::-webkit-scrollbar-thumb:hover {
        background-color: var(--text-color);
      }

      /* Mermaid图表样式 */
      .mermaid {
        margin: 1.5em 0;
        text-align: center;
        background: var(--editor-bg);
        padding: 1em;
        border-radius: 8px;
        border: 1px solid var(--border-color);
        overflow-x: auto;
      }

      .mermaid svg {
        max-width: 100%;
        height: auto;
      }

      /* 深色模式下的Mermaid样式 */
      [data-theme="dark"] .mermaid {
        --mermaid-bg: var(--editor-bg);
        --mermaid-fg: var(--text-color);
        --mermaid-edge: var(--text-color);
        --mermaid-label: var(--text-color);
        --mermaid-cluster: var(--border-color);
      }

      [data-theme="dark"] .mermaid .node rect,
      [data-theme="dark"] .mermaid .node circle,
      [data-theme="dark"] .mermaid .node ellipse,
      [data-theme="dark"] .mermaid .node polygon,
      [data-theme="dark"] .mermaid .node path {
        fill: var(--mermaid-bg);
        stroke: var(--mermaid-fg);
      }

      [data-theme="dark"] .mermaid .edgePath .path {
        stroke: var(--mermaid-edge) !important;
      }

      [data-theme="dark"] .mermaid .edgeLabel {
        color: var(--mermaid-label);
        background-color: var(--mermaid-bg);
      }

      [data-theme="dark"] .mermaid .cluster rect {
        fill: var(--mermaid-bg) !important;
        stroke: var(--mermaid-cluster) !important;
      }

      [data-theme="dark"] .mermaid .label {
        color: var(--mermaid-label);
      }

      [data-theme="dark"] .mermaid .node .label {
        color: var(--mermaid-label);
      }

      [data-theme="dark"] .mermaid marker {
        fill: var(--mermaid-edge);
      }
    </style>

    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/emoji-toolkit@7.0.0/lib/js/joypixels.min.js"></script>
    <script src="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.9.0/build/highlight.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/emoji-toolkit@7.0.0/extras/css/joypixels.min.css">
  </head>
  <body>
    <div class="container">
      <div class="toolbar">
        <div class="toolbar-left">
          <div class="note-name" onclick="copyNoteLink()" title="点击复制链接">
            📋 ${noteName}
          </div>
          <div class="toolbar-divider"></div>
          <!-- 字体和字号选择器 -->
          <select id="font-family" class="toolbar-select" onchange="applyFont()">
            <option value="default">默认字体</option>
            <option value="serif">宋体</option>
            <option value="yahei">微软雅黑</option>
            <option value="kaiti">楷体</option>
            <option value="heiti">黑体</option>
            <option value="fangsong">仿宋</option>
            <option value="songti">新宋体</option>
            <option value="monospace">等宽字体</option>
            <option value="arial">Arial</option>
            <option value="times">Times New Roman</option>
            <option value="helvetica">Helvetica</option>
          </select>
          <select id="font-size" class="toolbar-select" onchange="applyFontSize()">
            <option value="12">12px</option>
            <option value="13">13px</option>
            <option value="14">14px</option>
            <option value="15">15px</option>
            <option value="16" selected>16px</option>
            <option value="17">17px</option>
            <option value="18">18px</option>
            <option value="20">20px</option>
            <option value="22">22px</option>
            <option value="24">24px</option>
            <option value="26">26px</option>
            <option value="28">28px</option>
            <option value="32">32px</option>
          </select>
          <div class="toolbar-divider"></div>
          <!-- Markdown 工具栏 -->
          <div class="markdown-toolbar">
            <button onclick="applyMarkdown('bold')" title="粗体 Ctrl+B">B</button>
            <button onclick="applyMarkdown('italic')" title="斜体 Ctrl+I">I</button>
            <button onclick="applyMarkdown('heading')" title="标题 Ctrl+H">H</button>
            <button onclick="applyMarkdown('strikethrough')" title="删除线 Ctrl+D">S</button>
            <button onclick="applyMarkdown('list')" title="无序列表 Ctrl+U">•</button>
            <button onclick="applyMarkdown('ordered-list')" title="有序列表 Ctrl+O">1.</button>
            <button onclick="applyMarkdown('task')" title="任务列表 Ctrl+T">☐</button>
            <button onclick="applyMarkdown('quote')" title="引用 Ctrl+Q">""</button>
            <button onclick="applyMarkdown('code')" title="代码 Ctrl+K">{}</button>
            <button onclick="applyMarkdown('table')" title="表格">⚏</button>
            <button onclick="applyMarkdown('divider')" title="分割线">—</button>
            <button onclick="applyMarkdown('link')" title="链接 Ctrl+L">🔗</button>
            <button onclick="applyMarkdown('image')" title="图片 Ctrl+P">🖼</button>
            <button onclick="showEmojiPicker()" title="表情">😊</button>
            <div class="toolbar-divider"></div>
            <button onclick="applyMarkdown('latex-inline')" title="行内公式">∑</button>
            <button onclick="applyMarkdown('latex-block')" title="公式块">∫</button>
            <button onclick="applyMarkdown('mermaid')" title="流程图">📊</button>
          </div>
          <span id="save-status"></span>
        </div>
        <div class="toolbar-right">
          <div class="password-status toolbar-button" onclick="showPasswordDialog()" title="密码保护设置">
            <span class="icon" id="password-status-icon">🔓</span>
            <span class="label">密码保护</span>
          </div>
          <button onclick="toggleDarkMode()" class="toolbar-button theme-toggle" title="切换主题">
            <div class="icon">
              <span class="sun-icon">☀️</span>
              <span class="moon-icon">🌙</span>
            </div>
            <span class="label">主题</span>
          </button>
          <div class="share-button toolbar-button" onclick="shareNote()" title="分享笔记">
            <span class="icon">📤</span>
            <span class="label">分享</span>
          </div>
        </div>
      </div>

      <div class="editor-container">
        <div class="editor-wrapper">
          <div class="editor-main">
            <div class="line-numbers"></div>
            <textarea id="content" placeholder="开始输入笔记内容..." onscroll="handleEditorScroll()">${noteContent}</textarea>
          </div>
          <div class="status-bar">
            <div class="status-left">
              <div class="status-item">
                <label title="显示/隐藏行号">
                  <input type="checkbox" id="line-numbers-toggle" checked onchange="toggleLineNumbers()">
                  行号
                </label>
              </div>
              <div class="status-item">
                <label title="显示/隐藏工具栏">
                  <input type="checkbox" id="toolbar-toggle" checked onchange="toggleToolbar()">
                  工具栏
                </label>
              </div>
              <div class="status-item">
                <label class="switch-label">
                  <input type="checkbox" id="preview-toggle" onchange="togglePreview()">
                  预览
                </label>
              </div>
            </div>
            <div class="status-right">
              <div class="status-item copy-all-item" onclick="copyAllContent()" title="复制全部内容">
                <span class="copy-icon">📋</span>
                <span>复制全部</span>
              </div>
              <div class="status-item">
                <span>字数:</span>
                <span id="char-count">0</span>
              </div>
              <div class="status-item">
                <span>单词:</span>
                <span id="word-count">0</span>
              </div>
              <div class="status-item">
                <span>行:</span>
                <span id="line-count">1</span>
              </div>
              <div class="status-item">
                <span>列:</span>
                <span id="column-count">1</span>
              </div>
            </div>
          </div>
        </div>
        <div id="preview" class="preview-container">
          <div class="preview-content" onscroll="handlePreviewScroll()" ondblclick="handlePreviewDoubleTap(event)"></div>
          <div class="preview-status-bar">
            <div class="preview-status-left">
              <button onclick="togglePreviewFullscreen()" class="fullscreen-toggle" title="切换全屏">
                <span class="fullscreen-icon" id="fullscreen-icon">⛶</span>
              </button>
              <div class="preview-status-item">
                <label class="switch-label">
                  <input type="checkbox" id="sync-scroll-toggle" onchange="toggleSyncScroll()">
                  同步滚动
                </label>
              </div>
            </div>
            <div class="preview-status-right">
              <div class="preview-status-item">
                <span>字数:</span>
                <span id="preview-char-count">0</span>
              </div>
              <div class="preview-status-item">
                <span>单词:</span>
                <span id="preview-word-count">0</span>
              </div>
              <div class="preview-status-item">
                <span>段落:</span>
                <span id="preview-paragraph-count">0</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div id="emoji-picker" class="emoji-picker"></div>
    
    <!-- 添加密码对话框 -->
    <div class="password-dialog-overlay" id="password-overlay"></div>
    <div class="password-dialog" id="password-dialog">
      <h3 id="password-dialog-title">设置密码保护</h3>
      <input type="password" id="password-input" placeholder="请输入密码" autocomplete="new-password">
      <div class="password-dialog-message" id="password-message"></div>
      <div class="password-dialog-buttons">
        <button onclick="closePasswordDialog()">
          <span>取消</span>
        </button>
        <button class="primary" onclick="handlePasswordAction()" id="password-action-btn">
          <span>确定</span>
        </button>
      </div>
    </div>

    <!-- 添加 Toast 容器 -->
    <div class="toast-container" id="toast-container"></div>

    <div class="image-overlay" id="imageOverlay" onclick="closeEnlargedImage()"></div>

    <script>
      const content = document.getElementById('content');
      const preview = document.getElementById('preview');
      const previewToggle = document.getElementById('preview-toggle');
      const syncScrollToggle = document.getElementById('sync-scroll-toggle');
      const saveStatus = document.getElementById('save-status');
      let saveTimeout;
      let isEditorScrolling = false;
      let isPreviewScrolling = false;
      let isSyncScrollEnabled = true;
	  let isEmptyNote = false; // Flag to track if the note is empty and space was added

      document.addEventListener('DOMContentLoaded', () => {
        // 配置 marked
        marked.setOptions({
          gfm: true,
          breaks: true,
          tables: true,
          headerIds: true,
          mangle: false,
          sanitize: false,
          smartLists: true,
          smartypants: true,
          xhtml: false,
          langPrefix: 'language-',
          pedantic: false,
          highlight: function(code, lang) {
            if (lang && hljs.getLanguage(lang)) {
              try {
                return hljs.highlight(code, { language: lang }).value;
              } catch (err) {}
            }
            try {
              return hljs.highlightAuto(code).value;
            } catch (err) {}
            return code;
          }
        });

        // 自定义 emoji 渲染
        const renderer = new marked.Renderer();
        const originalText = renderer.text.bind(renderer);
        renderer.text = (text) => {
          return joypixels.shortnameToImage(originalText(text));
        };
        marked.setOptions({ renderer });

        // 初始化主题
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);

        // 初始化预览状态
        const showPreview = localStorage.getItem('preview') === 'true';
        previewToggle.checked = showPreview;
        
        // 初始化同步滚动状态
        const savedSyncScroll = localStorage.getItem('sync-scroll');
        isSyncScrollEnabled = savedSyncScroll !== 'false';
        syncScrollToggle.checked = isSyncScrollEnabled;
        
        const editorContainer = document.querySelector('.editor-container');
        editorContainer.classList.toggle('preview-mode', showPreview);
        preview.style.display = showPreview ? 'block' : 'none';
        
        if (showPreview) {
          updatePreview(content.value);
        }

        content.addEventListener('input', () => {
          updatePreview(content.value);
		  
		  // If the content becomes empty, insert a space to trigger the save
		  if (content.value.trim().length === 0) {
			  if (!isEmptyNote) {
			  content.value = ' '; // Automatically add a space if content is empty
			  saveStatus.textContent = 'Note will be deleted'; // Notify the user that the note will be deleted
			  isEmptyNote = true; // Flag that space was added
			  }
		  } else {
			  // If content is no longer empty, remove the space and update status
			  if (isEmptyNote) {
			  content.value = content.value.trim(); // Remove the space if user starts typing again
			  isEmptyNote = false; // Reset the flag
			  }
			  saveStatus.textContent = 'Saving...'; // Show saving status while content is being edited
		  }

          debounceSaveContent(content.value);
        });

        window.addEventListener('resize', () => {
          if (previewToggle.checked) {
            syncScrollPositions('editor');
          }
        });

        // 初始化行号显示状态
        const showLineNumbers = localStorage.getItem('show-line-numbers') !== 'false';
        document.getElementById('line-numbers-toggle').checked = showLineNumbers;
        const lineNumbers = document.querySelector('.line-numbers');
        lineNumbers.classList.toggle('hidden', !showLineNumbers);

        // 初始化行号和文本统计
        updateLineNumbers();
        updateTextStats();

        // 初始化工具栏显示状态
        const showToolbar = localStorage.getItem('show-toolbar') !== 'false';
        document.getElementById('toolbar-toggle').checked = showToolbar;
        const toolbar = document.querySelector('.toolbar');
        const container = document.querySelector('.container');
        toolbar.classList.toggle('hidden', !showToolbar);
        container.classList.toggle('toolbar-hidden', !showToolbar);

        // 恢复全屏状态
        const savedFullscreen = localStorage.getItem('preview-fullscreen') === 'true';
        if (savedFullscreen) {
          togglePreviewFullscreen();
        }

        // 添加 Firefox 双击事件监听
        const previewContent = document.querySelector('.preview-content');
        if (previewContent) {
          previewContent.addEventListener('mousedown', (e) => {
            if (e.detail === 2) { // 检测双击
              e.preventDefault(); // 阻止默认的文本选择
            }
          });
        }

        // 添加工具栏鼠标滚动支持
        let isMouseDown = false;
        let startX;
        let scrollLeft;

        toolbar.addEventListener('mousedown', (e) => {
          isMouseDown = true;
          toolbar.classList.add('dragging');
          startX = e.pageX - toolbar.offsetLeft;
          scrollLeft = toolbar.scrollLeft;
        });

        toolbar.addEventListener('mouseleave', () => {
          isMouseDown = false;
          toolbar.classList.remove('dragging');
        });

        toolbar.addEventListener('mouseup', () => {
          isMouseDown = false;
          toolbar.classList.remove('dragging');
        });

        toolbar.addEventListener('mousemove', (e) => {
          if (!isMouseDown) return;
          e.preventDefault();
          const x = e.pageX - toolbar.offsetLeft;
          const walk = (x - startX) * 2;
          toolbar.scrollLeft = scrollLeft - walk;
        });

        // 支持鼠标滚轮横向滚动
        toolbar.addEventListener('wheel', (e) => {
          e.preventDefault();
          toolbar.scrollLeft += e.deltaY;
        });
      });

      function togglePreview() {
        const showPreview = previewToggle.checked;
        const editorContainer = document.querySelector('.editor-container');
        
        editorContainer.classList.toggle('preview-mode', showPreview);
        preview.style.display = showPreview ? 'block' : 'none';
        
        localStorage.setItem('preview', showPreview);
        
        if (showPreview) {
          updatePreview(content.value);
          setTimeout(() => syncScrollPositions('editor'), 100);
        }
      }

      function toggleSyncScroll() {
        isSyncScrollEnabled = syncScrollToggle.checked;
        localStorage.setItem('sync-scroll', isSyncScrollEnabled);
      }

      function updatePreview(text) {
        if (previewToggle.checked) {
          const previewContent = preview.querySelector('.preview-content');
          const scrollPos = previewContent.scrollTop;
          
          // 渲染Markdown内容
          previewContent.innerHTML = marked.parse(text);
          
          // 渲染LaTeX公式
          renderMathInElement(previewContent, {
            delimiters: [
              {left: '$$', right: '$$', display: true},
              {left: '$', right: '$', display: false},
              // 移除普通方括号作为数学公式的标记
              // {left: '\\[', right: '\\]', display: true},
              // 替换为更明确的数学公式标记
              {left: 'math\\[', right: '\\]', display: true},
              {left: '\\(', right: '\\)', display: false},
              {left: '\\begin{align}', right: '\\end{align}', display: true}, // 添加对 align 环境的支持
            ],
            throwOnError: false,
            output: 'html'
          });

          // 渲染Mermaid图表
          mermaid.initialize({
            startOnLoad: false,
            theme: document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'default',
            securityLevel: 'loose',
            fontFamily: 'var(--font-family)',
          });

          const mermaidDiagrams = previewContent.querySelectorAll('pre code.language-mermaid');
          mermaidDiagrams.forEach(async (diagram, index) => {
            try {
              const pre = diagram.parentElement;
              const mermaidDiv = document.createElement('div');
              mermaidDiv.className = 'mermaid';
              mermaidDiv.id = 'mermaid-' + Date.now() + '-' + index; // 添加唯一ID
              mermaidDiv.textContent = diagram.textContent;
              pre.parentNode.replaceChild(mermaidDiv, pre);
            } catch (error) {
              console.error('Mermaid渲染错误:', error);
            }
          });

          // 等待所有图表渲染完成
          if (mermaidDiagrams.length > 0) {
            mermaid.run();
          }
          
          // 更新预览区统计信息
          updatePreviewStats(text);
          
          // 为所有代码块添加复制按钮和语言标签
          const codeBlocks = previewContent.querySelectorAll('pre code');
          codeBlocks.forEach(code => {
            const pre = code.parentElement;
            // 跳过Mermaid图表
            if (code.classList.contains('language-mermaid')) return;
            
            // 获取语言类名
            const langClass = Array.from(code.classList).find(cl => cl.startsWith('language-'));
            const language = langClass ? langClass.replace('language-', '') : '代码';
            // 设置语言标签
            pre.setAttribute('data-language', language);
            
            // 添加复制按钮
            if (!pre.querySelector('.copy-button')) {
              const button = document.createElement('button');
              button.className = 'copy-button';
              button.innerHTML = '📋 复制';
              button.onclick = (e) => {
                e.preventDefault();
                copyToClipboard(code.innerText, button);
              };
              pre.appendChild(button);
            }
          });

          // 重新应用代码高亮
          hljs.highlightAll();

          previewContent.scrollTop = scrollPos;
        }
      }

      async function copyToClipboard(text, button) {
        try {
          await navigator.clipboard.writeText(text);
          const originalText = button.innerHTML;
          button.innerHTML = '✅ 已复制';
          button.classList.add('copied');
          setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('copied');
          }, 2000);
        } catch (err) {
          console.error('复制失败:', err);
          button.innerHTML = '❌ 复制失败';
          setTimeout(() => {
            button.innerHTML = '📋 复制';
          }, 2000);
        }
      }

      function handleEditorScroll() {
        if (!isPreviewScrolling && previewToggle.checked && isSyncScrollEnabled) {
          isEditorScrolling = true;
          syncScrollPositions('editor');
          setTimeout(() => { isEditorScrolling = false; }, 50);
        }
      }

      function handlePreviewScroll() {
        if (!isEditorScrolling && previewToggle.checked && isSyncScrollEnabled) {
          isPreviewScrolling = true;
          const previewContent = preview.querySelector('.preview-content');
          const editorHeight = content.scrollHeight - content.clientHeight;
          const previewHeight = previewContent.scrollHeight - previewContent.clientHeight;
          
          if (previewHeight > 0) {
            const scrollPercentage = previewContent.scrollTop / previewHeight;
            content.scrollTop = scrollPercentage * editorHeight;
          }
          setTimeout(() => { isPreviewScrolling = false; }, 50);
        }
      }

      function syncScrollPositions(source) {
        if (!previewToggle.checked || !isSyncScrollEnabled) return;

        const editor = content;
        const previewContent = preview.querySelector('.preview-content');
        const editorHeight = editor.scrollHeight - editor.clientHeight;
        const previewHeight = previewContent.scrollHeight - previewContent.clientHeight;

        if (source === 'editor' && editorHeight > 0) {
          const scrollPercentage = editor.scrollTop / editorHeight;
          previewContent.scrollTop = scrollPercentage * previewHeight;
        } else if (source === 'preview' && previewHeight > 0) {
          const scrollPercentage = previewContent.scrollTop / previewHeight;
          editor.scrollTop = scrollPercentage * editorHeight;
        }
      }

      function debounceSaveContent(text) {
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(() => saveContent(text), 1000);
      }

      async function saveContent(text) {
        try {
          const response = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'text=' + encodeURIComponent(text),
          });

          saveStatus.textContent = response.status === 204 ? '已保存' : '笔记将被删除';
        } catch (error) {
          saveStatus.textContent = '保存失败';
        }

        setTimeout(() => {
          saveStatus.textContent = '';
        }, 2000);
      }

      // 添加 Toast 提示框功能
      function showToast(message, type = 'info', duration = 3000) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        
        // 设置图标
        const icons = {
          success: '✅',
          error: '❌',
          info: 'ℹ️',
          warning: '⚠️'
        };
        
        toast.innerHTML = 
          '<span class="toast-icon">' + (icons[type] || icons.info) + '</span>' +
          '<span class="toast-message">' + message + '</span>' +
          '<span class="toast-close" onclick="this.parentElement.remove()">✕</span>';
        
        container.appendChild(toast);
        
        // 触发重排以启动动画
        void toast.offsetWidth;
        toast.classList.add('show');
        
        // 自动关闭
        setTimeout(() => {
          toast.classList.remove('show');
          setTimeout(() => toast.remove(), 300);
        }, duration);
      }

      // 替换原有的 alert 调用
      function copyNoteLink() {
        const link = window.location.href;
        navigator.clipboard.writeText(link).then(() => {
          showToast('笔记链接已复制到剪贴板！', 'success');
        }).catch(() => {
          showToast('复制失败，请手动复制链接。', 'error');
        });
      }

      function toggleDarkMode() {
        const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        // 更新Mermaid主题
        mermaid.initialize({
          startOnLoad: false,
          theme: theme === 'dark' ? 'dark' : 'default',
          securityLevel: 'loose',
          fontFamily: 'var(--font-family)',
        });
        
        // 重新渲染预览内容以更新Mermaid图表
        if (previewToggle.checked) {
          updatePreview(content.value);
        }
      }

      // Markdown 编辑功能
      function applyMarkdown(type) {
        const textarea = document.getElementById('content');
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const text = textarea.value;
        let result;

        switch(type) {
          case 'bold':
            result = insertAround(text, start, end, '**');
            break;
          case 'italic':
            result = insertAround(text, start, end, '_');
            break;
          case 'heading':
            result = insertAtLineStart(text, start, '# ');
            break;
          case 'strikethrough':
            result = insertAround(text, start, end, '~~');
            break;
          case 'list':
            result = insertAtLineStart(text, start, '- ');
            break;
          case 'ordered-list':
            result = insertAtLineStart(text, start, '1. ');
            break;
          case 'task':
            result = insertAtLineStart(text, start, '- [ ] ');
            break;
          case 'quote':
            result = insertAtLineStart(text, start, '> ');
            break;
          case 'code':
            result = insertAround(text, start, end, '\`\`\`\\n', '\\n\`\`\`');
            break;
          case 'table':
            result = insertTable(text, start);
            break;
          case 'divider':
            result = insertDivider(text, start);
            break;
          case 'link':
            result = insertLink(text, start, end);
            break;
          case 'image':
            result = insertImage(text, start, end);
            break;
          case 'latex-inline':
            result = insertAround(text, start, end, '$');
            break;
          case 'latex-block':
            result = insertAround(text, start, end, '$$\\n', '\\n$$');
            break;
          case 'mermaid':
            result = insertMermaid(text, start);
            break;
        }

        if (result) {
          textarea.value = result.text;
          textarea.selectionStart = result.selectionStart;
          textarea.selectionEnd = result.selectionEnd;
          textarea.focus();
          updatePreview(textarea.value);
          debounceSaveContent(textarea.value);
        }
      }

      // 辅助函数：在选中文本周围插入标记
      function insertAround(text, start, end, mark, endMark = mark) {
        const selection = text.substring(start, end);
        const before = text.substring(0, start);
        const after = text.substring(end);
        const newText = before + mark + selection + endMark + after;
        return {
          text: newText,
          selectionStart: start + mark.length,
          selectionEnd: end + mark.length
        };
      }

      // 辅助函数：在行首插入标记
      function insertAtLineStart(text, start, mark) {
        const lines = text.split('\\n');
        let currentPos = 0;
        let targetLine = 0;
        
        // 找到光标所在行
        for (let i = 0; i < lines.length; i++) {
          if (currentPos + lines[i].length >= start) {
            targetLine = i;
            break;
          }
          currentPos += lines[i].length + 1;
        }

        // 在目标行前添加标记
        lines[targetLine] = mark + lines[targetLine];
        
        return {
          text: lines.join('\\n'),
          selectionStart: currentPos + mark.length,
          selectionEnd: currentPos + mark.length
        };
      }

      // 插入表格
      function insertTable(text, start) {
        const tableTemplate = '\\n| 标题1 | 标题2 | 标题3 |\\n|--------|--------|--------|\\n| 内容1 | 内容2 | 内容3 |\\n';
        const newText = text.substring(0, start) + tableTemplate + text.substring(start);
        return {
          text: newText,
          selectionStart: start + tableTemplate.length,
          selectionEnd: start + tableTemplate.length
        };
      }

      // 添加插入Mermaid图表的函数
      function insertMermaid(text, start) {
        const mermaidTemplate = '\\n\`\`\`mermaid\\ngraph TD\\n    A[开始] --> B[步骤1]\\n    B --> C[步骤2]\\n    C --> D[结束]\\n\`\`\`\\n';
        const newText = text.substring(0, start) + mermaidTemplate + text.substring(start);
        return {
          text: newText,
          selectionStart: start + mermaidTemplate.length,
          selectionEnd: start + mermaidTemplate.length
        };
      }

      // 插入链接
      function insertLink(text, start, end) {
        const selection = text.substring(start, end).trim();
        const link = selection || '链接文字';
        const template = '[' + link + '](https://)';
        const newText = text.substring(0, start) + template + text.substring(end);
        return {
          text: newText,
          selectionStart: start + link.length + 3,
          selectionEnd: start + template.length - 1
        };
      }

      // 插入图片
      function insertImage(text, start, end) {
        const template = '![图片描述](https://)';
        return {
          text: text.substring(0, start) + template + text.substring(end),
          selectionStart: start + 2,
          selectionEnd: start + 6
        };
      }

      // 插入分割线
      function insertDivider(text, start) {
        const divider = '\\n---\\n';
        const newText = text.substring(0, start) + divider + text.substring(start);
        return {
          text: newText,
          selectionStart: start + divider.length,
          selectionEnd: start + divider.length
        };
      }

      // 字体设置
      function applyFont() {
        const select = document.getElementById('font-family');
        const textarea = document.getElementById('content');
        const fontMap = {
          'default': '',
          'serif': 'SimSun, serif',
          'yahei': '"Microsoft YaHei", "微软雅黑", sans-serif',
          'kaiti': 'KaiTi, "楷体", serif',
          'heiti': 'SimHei, "黑体", sans-serif',
          'fangsong': 'FangSong, "仿宋", serif',
          'songti': 'NSimSun, "新宋体", serif',
          'monospace': 'Monaco, Consolas, monospace',
          'arial': 'Arial, sans-serif',
          'times': '"Times New Roman", Times, serif',
          'helvetica': 'Helvetica, Arial, sans-serif'
        };
        textarea.style.fontFamily = fontMap[select.value] || '';
      }

      // 字号设置
      function applyFontSize() {
        const select = document.getElementById('font-size');
        const textarea = document.getElementById('content');
        textarea.style.fontSize = select.value + 'px';
      }

      // Emoji 选择器
      function showEmojiPicker() {
        const picker = document.getElementById('emoji-picker');
        const overlay = document.querySelector('.emoji-picker-overlay') || createOverlay();
        
        if (picker.style.display === 'block') {
          picker.style.display = 'none';
          overlay.style.display = 'none';
          return;
        }

        // 如果是第一次显示，初始化表情列表
        if (!picker.children.length) {
          const gridContainer = document.createElement('div');
          gridContainer.className = 'emoji-picker-grid';
          
          const emojis = ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', 
                         '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘',
                         '😗', '😙', '😚', '😋', '😛', '😝', '😜', '🤪',
                         '🤨', '🧐', '🤓', '😎', '🤩', '🥳', '😏', '😒',
                         '❤️', '🙌', '👍', '🎉', '✨', '🔥', '💡', '⭐',
                         '💪', '🎯', '✅', '❌', '💬', '👀', '🎨', '🎮',
                         '🎵', '🎬', '📚', '💻', '🔍', '⚡', '🌈', '🍀'];
          
          emojis.forEach(emoji => {
            const button = document.createElement('button');
            button.textContent = emoji;
            button.onclick = () => {
              insertEmoji(emoji);
              picker.style.display = 'none';
              overlay.style.display = 'none';
            };
            gridContainer.appendChild(button);
          });
          
          picker.appendChild(gridContainer);
        }

        overlay.style.display = 'block';
        picker.style.display = 'block';
      }

      // 创建遮罩层
      function createOverlay() {
        const overlay = document.createElement('div');
        overlay.className = 'emoji-picker-overlay';
        document.body.appendChild(overlay);
        
        overlay.addEventListener('click', () => {
          const picker = document.getElementById('emoji-picker');
          picker.style.display = 'none';
          overlay.style.display = 'none';
        });
        
        return overlay;
      }

      // 插入表情
      function insertEmoji(emoji) {
        const textarea = document.getElementById('content');
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const text = textarea.value;
        
        textarea.value = text.substring(0, start) + emoji + text.substring(end);
        textarea.selectionStart = textarea.selectionEnd = start + emoji.length;
        textarea.focus();
        
        updatePreview(textarea.value);
        debounceSaveContent(textarea.value);
      }

      // 添加快捷键支持
      document.addEventListener('keydown', function(e) {
        if (!e.ctrlKey) return;
        
        const shortcuts = {
          'b': 'bold',
          'i': 'italic',
          'h': 'heading',
          'd': 'strikethrough',
          'u': 'list',
          'o': 'ordered-list',
          't': 'task',
          'q': 'quote',
          'k': 'code',
          'l': 'link',
          'p': 'image'
        };

        if (shortcuts[e.key.toLowerCase()]) {
          e.preventDefault();
          applyMarkdown(shortcuts[e.key.toLowerCase()]);
        }
      });

      // 更新行号和调整布局
      function updateLineNumbers() {
        const textarea = document.getElementById('content');
        const lineNumbers = document.querySelector('.line-numbers');
        const fullText = textarea.value;
        const totalLines = fullText.endsWith('\\n') ? 
          fullText.split('\\n').length :
          fullText.split('\\n').length;
        
        // 清空现有行号
        lineNumbers.innerHTML = '';
        
        // 为每一行创建行号 span 元素
        for (let i = 0; i < totalLines; i++) {
          const span = document.createElement('span');
          span.textContent = i + 1;
          lineNumbers.appendChild(span);
        }

        // 确保至少有一行
        if (totalLines === 0) {
          const span = document.createElement('span');
          span.textContent = '1';
          lineNumbers.appendChild(span);
        }

        // 调整行号区域宽度
        const maxLineNumber = totalLines || 1;
        const minWidth = 28; // 最小宽度
        const digitWidth = 8; // 每个数字的估计宽度
        const newWidth = Math.max(minWidth, String(maxLineNumber).length * digitWidth + 8);
        lineNumbers.style.minWidth = newWidth + 'px';
      }

      // 监听窗口大小变化
      window.addEventListener('resize', () => {
        updateLineNumbers();
      });

      // 更新文本统计
      function updateTextStats() {
        const textarea = document.getElementById('content');
        const text = textarea.value;
        const position = textarea.selectionStart;

        // 计算字符数（不包括空格和换行）
        const charCount = text.replace(/\s/g, '').length;
        
        // 计算单词数
        const wordCount = text.trim().split(/\s+/).filter(word => word.length > 0).length;
        
        // 计算当前行和列
        const textBeforeCursor = text.substring(0, position);
        const lines = textBeforeCursor.split('\\n');
        const currentLine = lines.length;
        const currentLineContent = lines[lines.length - 1];
        const currentColumn = currentLineContent ? currentLineContent.length + 1 : 1;
        
        // 更新显示（使用更紧凑的格式）
        document.getElementById('char-count').textContent = String(charCount);
        document.getElementById('word-count').textContent = String(wordCount);
        document.getElementById('line-count').textContent = String(currentLine);
        document.getElementById('column-count').textContent = String(currentColumn);
      }

      // 同步滚动行号
      function syncLineNumbersScroll() {
        const textarea = document.getElementById('content');
        const lineNumbers = document.querySelector('.line-numbers');
        
        // 计算最大可滚动高度
        const maxScroll = textarea.scrollHeight - textarea.clientHeight;
        const currentScroll = textarea.scrollTop;
        
        // 确保不会滚动过头
        if (currentScroll <= maxScroll) {
          lineNumbers.scrollTop = currentScroll;
        }
      }

      // 监听输入事件
      content.addEventListener('input', () => {
        updatePreview(content.value);
        updateLineNumbers();
        updateTextStats();
        debounceSaveContent(content.value);
        // 输入时也同步滚动
        syncLineNumbersScroll();
      });

      // 监听光标位置变化
      content.addEventListener('keyup', updateTextStats);
      content.addEventListener('click', updateTextStats);
      content.addEventListener('scroll', syncLineNumbersScroll);

      // 切换行号显示/隐藏
      function toggleLineNumbers() {
        const lineNumbers = document.querySelector('.line-numbers');
        const isVisible = document.getElementById('line-numbers-toggle').checked;
        lineNumbers.classList.toggle('hidden', !isVisible);
        localStorage.setItem('show-line-numbers', isVisible);
      }

      // 切换工具栏显示/隐藏
      function toggleToolbar() {
        const isVisible = document.getElementById('toolbar-toggle').checked;
        const toolbar = document.querySelector('.toolbar');
        const container = document.querySelector('.container');
        
        toolbar.classList.toggle('hidden', !isVisible);
        container.classList.toggle('toolbar-hidden', !isVisible);
        
        localStorage.setItem('show-toolbar', isVisible);
        
        // 触发一次窗口大小变化事件，以更新编辑器布局
        window.dispatchEvent(new Event('resize'));
      }

      // 添加预览区统计功能
      function updatePreviewStats(text) {
        // 计算字符数（不包括空格和换行）
        const charCount = text.replace(/\\s/g, '').length;
        
        // 计算单词数
        const wordCount = text.trim().split(/\\s+/).filter(word => word.length > 0).length;
        
        // 计算段落数（通过空行分隔）
        const paragraphCount = text.split(/\\n\\s*\\n/).filter(para => para.trim().length > 0).length;
        
        // 更新显示
        document.getElementById('preview-char-count').textContent = String(charCount);
        document.getElementById('preview-word-count').textContent = String(wordCount);
        document.getElementById('preview-paragraph-count').textContent = String(paragraphCount);
      }

      // 添加全屏切换功能
      function togglePreviewFullscreen() {
        const preview = document.getElementById('preview');
        const fullscreenIcon = document.getElementById('fullscreen-icon');
        const isFullscreen = preview.classList.contains('fullscreen');
        
        if (isFullscreen) {
          // 如果已经是容器全屏，切换到真实全屏
          if (document.fullscreenElement) {
            document.exitFullscreen();
          } else {
            preview.requestFullscreen();
          }
        } else {
          // 首次点击进入容器全屏
          preview.classList.add('fullscreen');
          fullscreenIcon.textContent = '⛶';
        }
        
        // 触发resize事件以更新布局
        window.dispatchEvent(new Event('resize'));
        
        // 保存全屏状态到本地存储
        localStorage.setItem('preview-fullscreen', preview.classList.contains('fullscreen'));
      }

      // ESC键退出全屏
      function handleFullscreenEsc(e) {
        if (e.key === 'Escape') {
          const preview = document.getElementById('preview');
          if (preview.classList.contains('fullscreen')) {
            preview.classList.remove('fullscreen');
            const fullscreenIcon = document.getElementById('fullscreen-icon');
            fullscreenIcon.textContent = '⛶';
            localStorage.setItem('preview-fullscreen', false);
          }
        }
      }

      // 监听浏览器全屏变化事件
      document.addEventListener('fullscreenchange', () => {
        const preview = document.getElementById('preview');
        const fullscreenIcon = document.getElementById('fullscreen-icon');
        
        if (!document.fullscreenElement && preview.classList.contains('fullscreen')) {
          // 从真实全屏退出时，也退出容器全屏
          preview.classList.remove('fullscreen');
          fullscreenIcon.textContent = '⛶';
          localStorage.setItem('preview-fullscreen', false);
        }
      });

      // 双击进入/退出全屏（移动端支持）
      function handlePreviewDoubleTap(e) {
        const preview = document.getElementById('preview');
        // 确保不是在状态栏上双击
        if (!e.target.closest('.preview-status-bar')) {
          e.preventDefault(); // 阻止默认行为
          // 清除任何可能的文本选择
          window.getSelection().removeAllRanges();
          togglePreviewFullscreen();
        }
      }

      // 添加密码相关功能
      let isPasswordProtected = false;
      let isPasswordVerified = false;
      let currentPasswordAction = '';

      async function checkPasswordProtection() {
        try {
          const response = await fetch(window.location.pathname + '/password-check', {
            method: 'GET',
          });
          
          if (response.status === 200) {
            isPasswordProtected = true;
            document.body.classList.add('password-protected'); // 添加密码保护状态类
            showPasswordVerification();
          }
          updatePasswordStatus();
        } catch (error) {
          console.error('检查密码保护状态失败:', error);
        }
      }

      function showPasswordMessage(message, isSuccess = false) {
        const messageEl = document.getElementById('password-message');
        messageEl.textContent = message;
        messageEl.classList.toggle('success', isSuccess);
        messageEl.classList.add('show');
        
        // 1秒后自动隐藏成功消息
        if (isSuccess) {
          setTimeout(() => {
            messageEl.classList.remove('show');
          }, 1000);
        }
      }

      function clearPasswordMessage() {
        const messageEl = document.getElementById('password-message');
        messageEl.classList.remove('show', 'success');
        messageEl.textContent = '';
      }

      function showPasswordDialog() {
        const dialog = document.getElementById('password-dialog');
        const overlay = document.getElementById('password-overlay');
        const title = document.getElementById('password-dialog-title');
        const actionBtn = document.getElementById('password-action-btn');
        const passwordInput = document.getElementById('password-input');
        
        clearPasswordMessage();
        
        if (isPasswordProtected && isPasswordVerified) {
          title.textContent = '移除密码保护';
          actionBtn.textContent = '移除';
          currentPasswordAction = 'remove';
        } else if (!isPasswordProtected) {
          title.textContent = '设置密码保护';
          actionBtn.textContent = '设置';
          currentPasswordAction = 'set';
        }
        
        dialog.style.display = 'block';
        overlay.style.display = 'block';
        passwordInput.focus();

        // 添加回车键事件监听
        passwordInput.onkeydown = (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            handlePasswordAction();
          }
        };
      }

      function showPasswordVerification() {
        const dialog = document.getElementById('password-dialog');
        const overlay = document.getElementById('password-overlay');
        const title = document.getElementById('password-dialog-title');
        const actionBtn = document.getElementById('password-action-btn');
        const passwordInput = document.getElementById('password-input');
        
        clearPasswordMessage();
        
        title.textContent = '请输入密码';
        actionBtn.textContent = '验证';
        currentPasswordAction = 'verify';
        
        dialog.style.display = 'block';
        overlay.style.display = 'block';
        passwordInput.focus();

        // 添加回车键事件监听
        passwordInput.onkeydown = (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            handlePasswordAction();
          }
        };
      }

      function closePasswordDialog() {
        const dialog = document.getElementById('password-dialog');
        const overlay = document.getElementById('password-overlay');
        const passwordInput = document.getElementById('password-input');
        
        dialog.style.display = 'none';
        overlay.style.display = 'none';
        passwordInput.value = '';
        passwordInput.onkeydown = null; // 移除回车键事件监听
        clearPasswordMessage();
      }

      async function handlePasswordAction() {
        const password = document.getElementById('password-input').value;
        if (!password) {
          showPasswordMessage('请输入密码');
          showToast('请输入密码', 'warning');
          return;
        }

        try {
          let response;
          switch (currentPasswordAction) {
            case 'set':
              response = await fetch(window.location.pathname + '/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: await hashPassword(password) })
              });
              if (response.status === 200) {
                isPasswordProtected = true;
                isPasswordVerified = true;
                document.body.classList.add('password-protected');
                updatePasswordStatus();
                showPasswordMessage('密码保护已设置', true);
                showToast('密码保护已设置', 'success');
                setTimeout(closePasswordDialog, 1500);
              }
              break;

            case 'verify':
              response = await fetch(window.location.pathname + '/password-verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: await hashPassword(password) })
              });
              if (response.status === 200) {
                isPasswordVerified = true;
                document.body.classList.remove('password-protected');
                updatePasswordStatus();
                showPasswordMessage('密码验证成功', true);
                showToast('密码验证成功', 'success');
                setTimeout(closePasswordDialog, 1500);
              } else {
                showPasswordMessage('密码错误');
                showToast('密码错误', 'error');
                return;
              }
              break;

            case 'remove':
              response = await fetch(window.location.pathname + '/password', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: await hashPassword(password) })
              });
              if (response.status === 200) {
                isPasswordProtected = false;
                isPasswordVerified = false;
                document.body.classList.remove('password-protected');
                updatePasswordStatus();
                showPasswordMessage('密码保护已移除', true);
                showToast('密码保护已移除', 'success');
                setTimeout(closePasswordDialog, 1500);
              } else {
                showPasswordMessage('密码错误');
                showToast('密码错误', 'error');
                return;
              }
              break;
          }
        } catch (error) {
          console.error('密码操作失败:', error);
          showPasswordMessage('操作失败，请重试');
          showToast('操作失败，请重试', 'error');
        }
      }

      async function hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }

      function updatePasswordStatus() {
        const icon = document.getElementById('password-status-icon');
        const label = icon.nextElementSibling;
        if (isPasswordProtected) {
          icon.textContent = '🔒';
          icon.title = '已启用密码保护';
          label.textContent = '已加密';
        } else {
          icon.textContent = '🔓';
          icon.title = '未启用密码保护';
          label.textContent = '密码保护';
        }
      }

      // 在页面加载时检查密码保护状态
      document.addEventListener('DOMContentLoaded', async () => {
        await checkPasswordProtection();
        // ... existing DOMContentLoaded code ...
      });

      // 修改复制全部内容功能，添加动效
      async function copyAllContent() {
        const copyAllItem = document.querySelector('.copy-all-item');
        const textarea = document.getElementById('content');
        const text = textarea.value;
        
        try {
          await navigator.clipboard.writeText(text);
          copyAllItem.classList.add('copied');
          setTimeout(() => copyAllItem.classList.remove('copied'), 500);
          showToast('已复制全部内容到剪贴板', 'success');
        } catch (err) {
          console.error('复制失败:', err);
          showToast('复制失败，请重试', 'error');
        }
      }

      async function shareNote() {
        const preview = document.querySelector('.preview-content');
        if (!preview) {
          showToast('请先开启预览模式', 'warning');
          return;
        }
      
        try {
          // 生成分享ID
          const shareId = Array.from({length: 8}, () => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 62)]).join('');
      
          // 准备分享数据
          const shareData = {
            content: preview.innerHTML,
            createTime: new Date().toISOString(),
            lastEditTime: new Date().toISOString(),
            visitCount: 0
          };
      
          // 保存分享数据
          const response = await fetch('/share/' + shareId, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(shareData)
          });
      
          if (response.ok) {
            // 生成分享链接
            const shareUrl = window.location.origin + '/share/' + shareId;
      
            // 复制链接到剪贴板
            await navigator.clipboard.writeText(shareUrl);
            showToast('分享链接已复制到剪贴板', 'success');
          } else {
            showToast('分享失败,请重试', 'error');
          }
        } catch (error) {
          console.error('分享失败:', error);
          showToast('分享失败,请重试', 'error');
        }
      }

      // 图片点击放大
      document.addEventListener('DOMContentLoaded', () => {
        const content = document.querySelector('.content');
        const overlay = document.getElementById('imageOverlay');

        content.addEventListener('click', (e) => {
          if (e.target.tagName === 'IMG' && !e.target.classList.contains('enlarged')) {
            e.target.classList.add('enlarged');
            overlay.classList.add('active');
            document.body.style.overflow = 'hidden';
          }
        });
      });

      // 关闭放大的图片
      function closeEnlargedImage() {
        const enlargedImage = document.querySelector('.enlarged');
        const overlay = document.getElementById('imageOverlay');
        
        if (enlargedImage) {
          enlargedImage.classList.remove('enlarged');
          overlay.classList.remove('active');
          document.body.style.overflow = '';
        }
      }

      // ESC键关闭放大图片
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          closeEnlargedImage();
        }
      });

      // 图片加载错误处理
      document.addEventListener('DOMContentLoaded', () => {
        const images = document.querySelectorAll('.content img');
        images.forEach(img => {
          img.onerror = () => {
            img.src = 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
          };
        });
      });
    </script>
  </body>
  </html>`;
}

/**
 * 从KV存储获取笔记内容
 * @param {string} notePath - 笔记路径
 * @returns {Promise<string>} 笔记内容
 */
async function getNoteContent(notePath) {
  const encryptedText = await NOTES_KV.get(notePath);
  if (!encryptedText) return '';
  
  const key = await generateEncryptionKey(notePath);
  return await decryptText(encryptedText, key);
}

/**
 * 保存笔记内容到KV存储
 * @param {string} notePath - 笔记路径
 * @param {string} text - 笔记内容
 */
async function saveNoteContent(notePath, text) {
  const key = await generateEncryptionKey(notePath);
  const encryptedText = await encryptText(text, key);
  await NOTES_KV.put(notePath, encryptedText);
}

/**
 * 从KV存储删除笔记
 * @param {string} notePath - 要删除的笔记路径
 */
async function deleteNoteContent(notePath) {
  await NOTES_KV.delete(notePath);
}

/**
 * 处理分享页面请求
 * @param {string} shareId - 分享ID
 * @returns {Response} 响应对象
 */
async function handleShareRequest(shareId) {
  // 获取分享数据
  const shareKey = 'share_' + shareId;
  const shareData = await NOTES_KV.get(shareKey);
  
  if (!shareData) {
    return new Response('分享内容不存在或已过期', { status: 404 });
  }

  try {
    const data = JSON.parse(shareData);
    // 更新访问次数
    data.visitCount++;
    await NOTES_KV.put(shareKey, JSON.stringify(data));
    
    // 生成分享页面
    const html = generateShareHTML(shareId, data);
    return new Response(html, { 
      headers: { 'Content-Type': 'text/html;charset=utf-8' }
    });
  } catch (error) {
    return new Response('加载分享内容失败', { status: 500 });
  }
}

/**
 * 生成分享页面HTML
 * @param {string} shareId - 分享ID
 * @param {Object} data - 分享数据
 * @returns {string} HTML内容
 */
function generateShareHTML(shareId, data) {
  const shareTime = new Date(data.createTime).toLocaleString('zh-CN');
  
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>分享的笔记</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.9.0/build/styles/github.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.9.0/build/styles/github-dark.min.css" media="(prefers-color-scheme: dark)">
  <!-- 添加KaTeX依赖 -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
  <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/contrib/auto-render.min.js"></script>
  <!-- 添加Mermaid依赖 -->
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10.6.1/dist/mermaid.min.js"></script>
  <style>
    :root {
      --primary-color: #4e92d1;
      --secondary-color: #6c757d;
      --bg-color: #ffffff;
      --text-color: #333333;
      --border-color: #e0e0e0;
      --container-bg: #ffffff;
      --editor-bg: #f8f8f8;
      --shadow-color: rgba(0, 0, 0, 0.1);
      --hover-color: #f0f0f0;
      --link-color: #0366d6;
      --link-hover-color: #0969da;
      --link-visited-color: #6f42c1;
    }

    [data-theme="dark"] {
      --primary-color: #a2c2f5;
      --secondary-color: #9ca3af;
      --bg-color: #1a1a1a;
      --text-color: #f1f1f1;
      --border-color: #404040;
      --container-bg: #2a2a2a;
      --editor-bg: #333333;
      --shadow-color: rgba(0, 0, 0, 0.3);
      --hover-color: #3a3a3a;
      --link-color: #58a6ff;
      --link-hover-color: #79b8ff;
      --link-visited-color: #bc8cff;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      margin: 0;
      background: var(--bg-color);
      color: var(--text-color);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 16px;
      line-height: 1.6;
      transition: all 0.3s ease;
    }

    .container {
      width: 100%;
      max-width: 100%;
      margin: 0 auto;
      padding: 20px;
      min-height: 100vh;
      background-color: var(--container-bg);
    }

    @media (min-width: 1200px) {
      .container {
        max-width: 95%;
        box-shadow: 0 0 20px var(--shadow-color);
      }
    }

    .info-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px;
      background: var(--editor-bg);
      border-radius: 12px;
      margin-bottom: 20px;
      font-size: 14px;
      border: 1px solid var(--border-color);
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: none;
      gap: 15px;
      min-width: 0;
    }

    .info-bar::-webkit-scrollbar {
      height: 6px;
      width: 6px;
    }

    .info-bar::-webkit-scrollbar-track {
      background: transparent;
    }
    .info-bar::-webkit-scrollbar-thumb {
      background-color: var(--secondary-color);
      border-radius: 3px;
    }

    .info-bar::-webkit-scrollbar-thumb:hover {
      background-color: var(--text-color);
    }

    .info-left {
      display: flex;
      gap: 15px;
      flex-shrink: 0;
      margin-right: auto;
    }

    .info-right {
      display: flex;
      align-items: center;
      gap: 15px;
      flex-shrink: 0;
      margin-left: auto;
    }

    .info-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px 10px;
      border-radius: 6px;
      transition: all 0.2s ease;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .info-item:hover {
      background: var(--hover-color);
    }

    .theme-toggle {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px 10px;
      border-radius: 6px;
      border: none;
      color: var(--text-color);
      cursor: pointer;
      font-size: 14px;
      transition: all 0.2s ease;
      background: transparent;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .theme-toggle:hover {
      background: var(--hover-color);
    }

    .theme-toggle:active {
      transform: scale(0.95);
    }

    .theme-toggle .sun-icon,
    .theme-toggle .moon-icon {
      display: none;
      font-size: 1.2rem;
    }

    .theme-toggle .label {
      font-size: 14px;
    }

    [data-theme="dark"] .moon-icon {
      display: block;
    }

    [data-theme="light"] .sun-icon {
      display: block;
    }

    @media (max-width: 768px) {
      .theme-toggle {
        padding: 4px 8px;
      }

      .theme-toggle .label {
        font-size: 13px;
      }
    }

    @media (max-width: 768px) {
      .info-bar {
        padding: 10px;
        gap: 10px;
      }

      .info-left,
      .info-right {
        gap: 10px;
      }

      .info-item {
        padding: 4px 8px;
        font-size: 13px;
      }
    }

    .content {
      padding: 20px;
      border: 1px solid var(--border-color);
      border-radius: 12px;
      background: var(--editor-bg);
      overflow-x: auto;
    }

    /* Markdown 内容样式 */
    .content > *:first-child {
      margin-top: 0;
    }

    .content > *:last-child {
      margin-bottom: 0;
    }

    .content h1,
    .content h2,
    .content h3,
    .content h4,
    .content h5,
    .content h6 {
      margin-top: 1.8em;
      margin-bottom: 0.8em;
      line-height: 1.2;
      color: var(--text-color);
    }

    .content h1:first-child,
    .content h2:first-child,
    .content h3:first-child,
    .content h4:first-child,
    .content h5:first-child,
    .content h6:first-child {
      margin-top: 0;
    }

    .content p {
      text-align: left !important;
      margin: 1.2em 0;
      line-height: 1.8;
    }

    .content p:has(> a:only-child) {
      text-align: left !important;
    }

    .content a {
      display: inline;
      color: var(--link-color);
      text-decoration: none;
      border-bottom: 1px solid transparent;
      transition: all 0.2s ease;
      padding: 2px 4px;
      margin: 0 -4px;
      border-radius: 4px;
      text-align: left !important;
    }

    /* 处理单独一行的链接 */
    .content p > a:only-child {
      display: inline-block;
      text-align: left !important;
      width: fit-content;
      margin-left: 0;
    }

    /* 处理图片链接的特殊情况 */
    .content p:has(img) {
      text-align: center;
      margin: 2em 0;
    }

    .content a:hover {
      background: var(--hover-color);
      color: var(--link-hover-color);
      border-bottom-color: var(--link-hover-color);
    }

    .content a:visited {
      color: var(--link-visited-color);
    }

    .content a:visited:hover {
      background: var(--hover-color);
      border-bottom-color: var(--link-visited-color);
    }

    .content a[href^="http"]::after {
      content: "↗";
      display: inline;
      margin-left: 2px;
      font-size: 0.9em;
      opacity: 0.6;
    }

    .content ul,
    .content ol {
      margin: 1em 0;
      padding-left: 1.5em;
    }

    .content li {
      margin: 0.5em 0;
    }

    .content blockquote {
      margin: 1.2em 0;
      padding: 1em 1.2em;
      border-left: 4px solid var(--border-color);
      background: var(--bg-color);
      border-radius: 0 4px 4px 0;
      display: flow-root;
      width: fit-content;
      max-width: 100%;
      box-shadow: 0 2px 4px var(--shadow-color);
      transition: all 0.2s ease;
    }

    .content blockquote > *:first-child {
      margin-top: 0;
    }

    .content blockquote > *:last-child {
      margin-bottom: 0;
    }

    .content blockquote p {
      margin: 0.8em 0;
      line-height: 1.6;
    }

    .content blockquote + blockquote {
      margin-top: -0.5em;
    }

    .content blockquote blockquote {
      margin: 0.8em 0;
      border-left-color: var(--secondary-color);
      background: var(--editor-bg);
      box-shadow: none;
    }

    .content pre {
      background: var(--editor-bg);
      padding: 1.2em 1em;
      border-radius: 8px;
      overflow: auto;
      position: relative;
      margin: 1.5em 0;
      font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
      line-height: 1.5;
      font-size: 0.95em;
      border: 1px solid var(--border-color);
      scrollbar-width: thin;
      scrollbar-color: var(--secondary-color) transparent;
    }

    .content code {
      background: var(--editor-bg);
      padding: 0.2em 0.4em;
      margin: 0 0.2em;
      border-radius: 4px;
      font-size: 0.9em;
      font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
      border: 1px solid var(--border-color);
    }

    .content pre code {
      background: none;
      padding: 0;
      margin: 0;
      font-size: 0.95em;
      white-space: pre;
      word-break: normal;
      word-wrap: normal;
      line-height: inherit;
      tab-size: 2;
      hyphens: none;
      border: none;
    }

    .content pre::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }

    .content pre::-webkit-scrollbar-track {
      background: transparent;
    }

    .content pre::-webkit-scrollbar-thumb {
      background-color: var(--secondary-color);
      border-radius: 3px;
      border: 2px solid var(--editor-bg);
    }

    .content pre::-webkit-scrollbar-thumb:hover {
      background-color: var(--text-color);
    }

    .content pre::before {
      content: attr(data-language);
      position: absolute;
      top: 0.5em;
      right: 0.5em;
      font-size: 0.85em;
      color: var(--secondary-color);
      padding: 0.2em 0.5em;
      border-radius: 3px;
      background: var(--container-bg);
      opacity: 0.8;
      transition: opacity 0.2s ease;
    }

    .content pre:hover::before {
      opacity: 1;
    }

    .copy-button {
      position: absolute;
      top: 0.5em;
      right: 0.5em;
      padding: 0.2em 0.5em;
      font-size: 0.85em;
      color: var(--text-color);
      background: var(--container-bg);
      border: 1px solid var(--border-color);
      border-radius: 3px;
      cursor: pointer;
      opacity: 0;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .content pre:hover .copy-button {
      opacity: 0.8;
    }

    .copy-button:hover {
      opacity: 1 !important;
      background: var(--hover-color);
    }

    .copy-button.copied {
      color: #4caf50;
      border-color: #4caf50;
      opacity: 1;
    }

    /* Toast 提示框样式 */
    .toast-container {
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 10000;
      display: flex;
      flex-direction: column;
      gap: 10px;
      pointer-events: none;
    }

    .toast {
      background: var(--container-bg);
      color: var(--text-color);
      padding: 12px 24px;
      border-radius: 8px;
      box-shadow: 0 4px 12px var(--shadow-color);
      font-size: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      opacity: 0;
      transform: translateX(100%);
      transition: all 0.3s ease;
      border: 1px solid var(--border-color);
      pointer-events: all;
      max-width: 300px;
      word-break: break-word;
    }

    .toast.show {
      opacity: 1;
      transform: translateX(0);
    }

    .toast.success {
      border-left: 4px solid #4caf50;
    }

    .toast.error {
      border-left: 4px solid #f44336;
    }

    .toast-icon {
      font-size: 18px;
      flex-shrink: 0;
    }

    .toast-message {
      flex: 1;
      margin-right: 8px;
    }

    .toast-close {
      cursor: pointer;
      opacity: 0.7;
      transition: opacity 0.2s ease;
      padding: 4px;
      margin: -4px;
      border-radius: 4px;
    }

    .toast-close:hover {
      opacity: 1;
      background: var(--hover-color);
    }

    /* 表格样式 */
    .content table {
      width: 100%;
      border-collapse: collapse;
      margin: 1.5em 0;
      overflow-x: auto;
      display: block;
    }

    .content th,
    .content td {
      border: 1px solid var(--border-color);
      padding: 8px 12px;
      text-align: left;
    }

    .content th {
      background-color: var(--hover-color);
      font-weight: 600;
    }

    .content tr:nth-child(even) {
      background-color: var(--editor-bg);
    }

    .content tr:hover {
      background-color: var(--hover-color);
    }

    /* 移动端表格适配 */
    @media (max-width: 768px) {
      .content table {
        font-size: 14px;
      }

      .content th,
      .content td {
        padding: 6px 8px;
      }
    }

    /* 表格滚动条样式 */
    .content table::-webkit-scrollbar {
      height: 8px;
      width: 8px;
    }

    .content table::-webkit-scrollbar-track {
      background: transparent;
    }

    .content table::-webkit-scrollbar-thumb {
      background-color: var(--secondary-color);
      border-radius: 4px;
      border: 2px solid var(--editor-bg);
    }

    .content table::-webkit-scrollbar-thumb:hover {
      background-color: var(--text-color);
    }

    /* 图片样式 */
    .content img {
      max-width: 100%;
      height: auto;
      margin: 1em 0;
      border-radius: 8px;
      display: block;
      box-shadow: 0 2px 8px var(--shadow-color);
      transition: all 0.3s ease;
      opacity: 0;
      animation: fadeIn 0.5s ease forwards;
    }

    /* 图片容器 */
    .content p:has(img) {
      text-align: center;
      margin: 2em 0;
    }

    /* 图片悬停效果 */
    .content img:hover {
      transform: scale(1.01);
      box-shadow: 0 4px 12px var(--shadow-color);
    }

    /* 图片标题样式 */
    .content img + em {
      display: block;
      text-align: center;
      color: var(--secondary-color);
      font-size: 0.9em;
      margin-top: 0.5em;
    }

    /* 移动端图片适配 */
    @media (max-width: 768px) {
      .content img {
        border-radius: 6px;
        margin: 0.8em 0;
      }

      .content p:has(img) {
        margin: 1.5em 0;
      }

      /* 禁用移动端图片缩放动画 */
      .content img:hover {
        transform: none;
        box-shadow: 0 2px 8px var(--shadow-color);
      }
    }

    /* 图片加载动画 */
    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    /* 图片加载失败样式 */
    .content img:not([src]),
    .content img[src=""],
    .content img[src*="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="] {
      position: relative;
      min-height: 100px;
      background: var(--editor-bg);
      border: 1px dashed var(--border-color);
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .content img:not([src])::after,
    .content img[src=""]::after,
    .content img[src*="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="]::after {
      content: "图片加载失败";
      position: absolute;
      color: var(--secondary-color);
      font-size: 0.9em;
    }

    /* 大图查看模式 */
    .content img.enlarged {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      max-width: 90vw;
      max-height: 90vh;
      object-fit: contain;
      z-index: 1000;
      cursor: zoom-out;
      margin: 0;
      padding: 0;
      background: var(--bg-color);
      box-shadow: 0 0 20px var(--shadow-color);
    }

    /* 大图查看遮罩层 */
    .image-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      z-index: 999;
      display: none;
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .image-overlay.active {
      display: block;
      opacity: 1;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="info-bar">
      <div class="info-left">
        <div class="info-item">
          <span>📝 笔记</span>
          <span>${shareId}</span>
        </div>
        <div class="info-item">
          <span>🕒 分享于</span>
          <span>${shareTime}</span>
        </div>
        <div class="info-item">
          <span>👀 访问</span>
          <span>${data.visitCount}</span>
        </div>
      </div>
      <div class="info-right">
        <button onclick="toggleDarkMode()" class="theme-toggle" title="切换主题">
          <span class="sun-icon">☀️</span>
          <span class="moon-icon">🌙</span>
          <span class="label">主题</span>
        </button>
      </div>
    </div>
    <div class="content">
      ${data.content}
    </div>
  </div>

  <div class="image-overlay" id="imageOverlay" onclick="closeEnlargedImage()"></div>
  <div class="toast-container" id="toast-container"></div>

  <script src="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.9.0/build/highlight.min.js"></script>
  <script>
    // 初始化主题和代码块
    document.addEventListener('DOMContentLoaded', () => {
      const savedTheme = localStorage.getItem('theme') || 'light';
      document.documentElement.setAttribute('data-theme', savedTheme);
      
      // 为所有代码块添加复制按钮和语言标签
      const codeBlocks = document.querySelectorAll('pre code');
      codeBlocks.forEach(code => {
        const pre = code.parentElement;
        
        // 获取语言类名
        const langClass = Array.from(code.classList).find(cl => cl.startsWith('language-'));
        const language = langClass ? langClass.replace('language-', '') : '代码';
        pre.setAttribute('data-language', language);
        
        // 添加复制按钮
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.innerHTML = '<span>📋</span><span>复制</span>';
        button.onclick = async (e) => {
          e.preventDefault();
          e.stopPropagation();
          await copyCode(code, button);
        };
        pre.appendChild(button);
      });

      // 应用代码高亮
      hljs.highlightAll();

      // 图片点击放大
      const content = document.querySelector('.content');
      const overlay = document.getElementById('imageOverlay');

      content.addEventListener('click', (e) => {
        if (e.target.tagName === 'IMG' && !e.target.classList.contains('enlarged')) {
          e.target.classList.add('enlarged');
          overlay.classList.add('active');
          document.body.style.overflow = 'hidden';
        }
      });

      // 图片加载错误处理
      const images = document.querySelectorAll('.content img');
      images.forEach(img => {
        img.onerror = () => {
          img.src = 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
        };
      });
    });

    // 复制代码到剪贴板
    async function copyCode(codeElement, button) {
      const originalText = button.innerHTML;
      const code = codeElement.innerText;

      try {
        await navigator.clipboard.writeText(code);
        button.innerHTML = '<span>✅</span><span>已复制</span>';
        button.classList.add('copied');
        showToast('代码已复制到剪贴板', 'success');
      } catch (err) {
        console.error('复制失败:', err);
        button.innerHTML = '<span>❌</span><span>复制失败</span>';
        button.classList.add('error');
        showToast('复制失败，请重试', 'error');
      }

      setTimeout(() => {
        button.innerHTML = originalText;
        button.classList.remove('copied', 'error');
      }, 2000);
    }

    // 切换暗色模式
    function toggleDarkMode() {
      const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('theme', theme);
      
      // 更新Mermaid主题
      mermaid.initialize({
        startOnLoad: false,
        theme: theme === 'dark' ? 'dark' : 'default',
        securityLevel: 'loose',
        fontFamily: 'var(--font-family)',
      });
      
      // 重新渲染预览内容以更新Mermaid图表
      if (previewToggle.checked) {
        updatePreview(content.value);
      }
    }

    // 关闭放大的图片
    function closeEnlargedImage() {
      const enlargedImage = document.querySelector('.enlarged');
      const overlay = document.getElementById('imageOverlay');
      
      if (enlargedImage) {
        enlargedImage.classList.remove('enlarged');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
      }
    }

    // ESC键关闭放大图片
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeEnlargedImage();
      }
    });

    // Toast 提示框
    function showToast(message, type = 'info', duration = 3000) {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast ' + type;
      
      const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️'
      };
      
      toast.innerHTML = 
        '<span class="toast-icon">' + (icons[type] || icons.info) + '</span>' +
        '<span class="toast-message">' + message + '</span>' +
        '<span class="toast-close" onclick="this.parentElement.remove()">✕</span>';
      
      container.appendChild(toast);
      
      void toast.offsetWidth;
      toast.classList.add('show');
      
      setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
      }, duration);
    }
  </script>
</body>
</html>`;
}

// 监听所有fetch请求
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

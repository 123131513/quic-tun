const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('用法: node push_stream.js /path/to/video.(mp4|y4m)');
  process.exit(1);
}

let inputPath = path.resolve(args[0]);
const roomId = 1234;
const displayName = 'puppeteerclient';
const initialBitrate = 10_000_000; // 10 Mbps

let tempY4m = null;

(async () => {
    if (inputPath.endsWith('.mp4')) {
      tempY4m = path.join(os.tmpdir(), `temp_${Date.now()}.y4m`);
      console.log(`🔄 转换 ${inputPath} → ${tempY4m}`);
      try {
        execFileSync('ffmpeg', ['-i', inputPath, '-pix_fmt', 'yuv420p', '-f', 'yuv4mpegpipe', tempY4m], {
          stdio: 'inherit'
        });
      } catch {
        console.error('❌ ffmpeg 转换失败');
        process.exit(1);
      }
      inputPath = tempY4m;
    }
  
    // 创建临时用户数据目录
    const userDataDir = path.join(os.tmpdir(), `chrome-profile-${Date.now()}`);
    fs.mkdirSync(userDataDir, { recursive: true });
    
    const browser = await puppeteer.launch({
      headless: true,
      executablePath: '/usr/bin/google-chrome',
      // executablePath: '/usr/bin/firefox',
      args: [
        '--use-fake-ui-for-media-stream',
        // '--use-fake-device-for-media-stream',
        // `--use-file-for-fake-video-capture=${inputPath}`,
        // '--no-sandbox',
        // '--autoplay-policy=no-user-gesture-required',
        // '--disable-features=MediaRouter',
        '--allow-file-access',
        '--allow-file-access-from-files',
        `--unsafely-treat-insecure-origin-as-secure=http://10.0.0.1:8080`,
        '--force-fieldtrials=WebRTC-LibvpxVp8EncoderFallback/Disabled/',
        '--disable-webrtc-hw-encoding',
        '--disable-webrtc-hw-decoding',
        '--disable-webrtc-automatic-resolution-scaling',
        '--disable-webrtc-automatic-simulcast-layer-selection',
        '--disable-features=WebRtcHideLocalIpsWithMdns',
        '--enable-features=WebRTC-DisableHWEncoding,WebRTC-DisableHWDecoding'
        // `--user-data-dir=${userDataDir}`,
        // '--enable-logging=stderr',
        // '--v=1'
      ],
      dumpio: true // 打印浏览器进程日志
    });
  
    const page = await browser.newPage();
    await page.setCacheEnabled(false);
    

    const version = Date.now();
    await page.goto(`http://10.0.0.1:8080/demos/videoroom.html?v=${version}`, {
      waitUntil: 'networkidle0',
      timeout: 30000
    });
  
    await page.waitForSelector('#start');
    await page.click('#start');
    console.log('🚀 已点击 Start');
  
    page.on('console', (msg) => {
      const type = msg.type();
      const text = msg.text();
      let prefix = '[页面日志]';
      if (type === 'error') prefix = '[页面错误]';
      if (type === 'warning') prefix = '[页面警告]';
      console.log(`${prefix} ${text}`);
    });
    
    page.on('request', req => console.log('[网络请求]', req.method(), req.url()));
    page.on('response', res => console.log('[网络响应]', res.status(), res.url()));
    
    // 等待注册界面
    await page.waitForFunction(() => {
      const e = document.querySelector('#registernow');
      return e && window.getComputedStyle(e).display !== 'none' && !e.classList.contains('hide');
    }, { timeout: 10000 });
    console.log('✅ 注册界面已显示');
  
    await page.waitForFunction(() => typeof window.registerUsername === 'function', { timeout: 30000 });
    console.log('✅ registerUsername 函数已定义');

    // Hook 注册函数

    await page.type('#username', displayName);
    await page.click('#register');
    console.log('✅ 点击注册');

    
    // 添加延迟等待初始化
    await new Promise(resolve => setTimeout(resolve, 5000));

    await page.screenshot({path: 'debug.png'});
    console.log('📸 已保存调试截图: debug.png');

    // 等待视频元素出现
    try {
      await page.waitForSelector('#videolocal video', { 
        visible: true, 
        timeout: 150000 
      });
      console.log('🎥 本地视频开始推流');
    } catch (e) {
      console.error('❌ 等待视频元素超时:', e.message);
      // 尝试截图调试
      await page.screenshot({path: 'debug.png'});
      console.log('📸 已保存调试截图: debug.png');
    }
  
    await page.waitForFunction(() => window.sfutest && typeof window.sfutest.send === 'function', { timeout: 10000 });
    await page.evaluate((bitrate) => {
      window.sfutest.send({
        message: {
          request: "configure",
          bitrate: bitrate
        }
      });
    }, initialBitrate);
    console.log(`✅ 已设置初始码率为 ${initialBitrate / 1000}kbps`);
  
    // 阻塞直到退出
    await new Promise((resolve) => {
      process.on('SIGINT', resolve);
      process.on('SIGTERM', resolve);
    });
  
    await browser.close();
    
    // 清理临时文件
    if (tempY4m && fs.existsSync(tempY4m)) {
      fs.unlinkSync(tempY4m);
      console.log(`🧹 删除临时文件: ${tempY4m}`);
    }
    
    // 清理用户数据目录
    fs.rmSync(userDataDir, { recursive: true, force: true });
    console.log(`🧹 删除用户数据目录: ${userDataDir}`);
})();
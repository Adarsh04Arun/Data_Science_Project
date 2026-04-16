darsh_run@LAPTOP-0M8KHQUG:~/DS_Final$ source .venv/bin/activate
(.venv) darsh_run@LAPTOP-0M8KHQUG:~/DS_Final$ nvm install 20
Downloading and installing node v20.20.1...
Downloading https://nodejs.org/dist/v20.20.1/node-v20.20.1-linux-x64.tar.xz...
################################################################################################################ 100.0%
Computing checksum with sha256sum
Checksums matched!
Now using node v20.20.1 (npm v10.8.2)
Creating default alias: default -> 20 (-> v20.20.1)
(.venv) darsh_run@LAPTOP-0M8KHQUG:~/DS_Final$ cd sentinel_ds
(.venv) darsh_run@LAPTOP-0M8KHQUG:~/DS_Final/sentinel_ds$ cd frontend
(.venv) darsh_run@LAPTOP-0M8KHQUG:~/DS_Final/sentinel_ds/frontend$ npm install

added 64 packages, and audited 65 packages in 14s

9 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities
npm notice
npm notice New major version of npm available! 10.8.2 -> 11.12.0
npm notice Changelog: https://github.com/npm/cli/releases/tag/v11.12.0
npm notice To update run: npm install -g npm@11.12.0
npm notice
(.venv) darsh_run@LAPTOP-0M8KHQUG:~/DS_Final/sentinel_ds/frontend$ npm run dev

> sentinel-dashboard@1.0.0 dev
> vite


  VITE v6.4.1  ready in 116 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
8:32:39 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16)
8:32:39 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x2)
8:32:44 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x3)
8:32:46 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x4)
8:32:49 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x5)
8:32:52 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x6)
8:32:55 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x7)
8:32:58 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x8)
8:33:01 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x9)
8:33:04 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x10)
8:33:07 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x11)
8:33:10 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x12)
8:33:13 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x13)
8:33:16 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x14)
8:33:19 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x15)
8:33:22 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x16)
8:33:25 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x17)
8:33:28 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x18)
8:33:31 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x19)
8:33:34 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x20)
8:33:37 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x21)
8:33:40 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x22)
8:36:10 AM [vite] http proxy error: /api/state
Error: connect ECONNREFUSED 127.0.0.1:8000
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16) (x23)
8:51:39 AM [vite] (client) hmr update /src/App.jsx
8:53:15 AM [vite] (client) hmr update /src/index.css
9:07:32 AM [vite] (client) hmr update /src/DataPipelineTab.jsx
9:08:23 AM [vite] (client) hmr update /src/DataPipelineTab.jsx (x2)
9:08:44 AM [vite] (client) hmr update /src/App.jsx
9:09:35 AM [vite] (client) hmr update /src/index.css





# 本地助记词加密（离网运行）

<img src="/demo/demo-screen.jpg?raw=true" width="500px"/>

助记词难记，放在 iCloud/百度云盘/阿里云/印象笔记/有道云笔记等在线存储中不安全。为了解决这个问题，我们可以用易记密码对助记词进行加密，然后将结果密文存储在在线存储中更安全。

加密/解密由使用 AES-GCM-256 的 WebCrypto API 完成，您可以参考[Mozilla 开发者网站](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)了解有关该 API 的更多详细信息。

该工具是一个独立的网页。每个人都可以将它下载到本地机器然后安全地执行它或直接尝试下面链接中的现场演示。
### 基于Cloudflare Workers实现的Markdown在线笔记  
#### 演示页面：https://mmnote.com/demo  (请不要修改或删除里面的内容)  
因KV按写入和读取次数计费，建议自行部署至Workers使用  
1、将代码复制粘贴至Workers & Pages中并命名,如mmnote，  
2、在Workers KV中建立NOTES_KV并与mmnote绑定即可使用，  
3、建议在Workers & Pages中设置绑定自己的域名使用。  

#### 功能说明：  
在线实时存储  
在线实时预览，预览区域可双击切换预览模式（默认、窗口全屏、屏幕全屏依次切换）  
密码保护（可锁定编辑区，方便下次编辑）  
分享  
浅色 深色模式  
已适配PC端和移动端  

#### 已知问题  
多行公式不能解析  
部分情况下输入时导致定位乱跳

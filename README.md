# protocol reverse

协议逆向

## reverse.py

获取协议格式

### 架构图

![架构图](pic/架构图.jpg)

### 环境依赖

+ python 2.7
+ ida pro 7
+ python-idb
+ vivisect

### 输入

idb文件 

### To-do List

- [x] 导入idb文件
  - [ ] idb问题：No handlers could be found for logger "idb.fileformat",原因：idb.fileformat:section class not implemented: id2
  - [ ] idb问题：idb库 功能不齐全
- [x] 筛选疑似函数
  - [x] 从import中筛选出通信函数
  - [ ] 添加其他通信函数
  - [x] 识别出通信函数的封装函数(疑似)
- [ ] - [ ] 长度
    - [ ] vivisect模块识别不到constants模块，未解决
  - [ ] 赋值
    - [ ] vivisect模块识别不到constants模块，未解决
  - [x] 循环
    - [x] 识别含有循环的函数，循环起始地址
  - [ ] 选择
- [ ] 输出
  - [ ] 协议特征
  - [ ] 设备特征
  - [ ] 上位机特征




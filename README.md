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
  + vivisect 老版本有兼容问题，更新至最新版

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
- [x] - [x] 长度

    - [x] vivisect 老版本兼容问题

    - [x] 获取封装函数参数
    - [ ] 自动化获取参数个数与判断是否为长度
    - [ ] 

  - [x] 赋值

    - [x] 遍历函数查看赋值情况
    - [ ] 判断有用的赋值
    - [ ] 数据在数据包中的位置

  - [x] 循环

    - [x] 识别含有循环的函数，循环起始地址

  - [x] 选择

    - [ ] 精确识别

    - [ ] 
- [ ] 输出
  - [ ] 协议特征
  - [ ] 设备特征
  - [ ] 上位机特征




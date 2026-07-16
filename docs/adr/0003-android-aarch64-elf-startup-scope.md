# 启动分析仅面向 Android AArch64 ELF

本项目的首版启动入口分析只支持 Android AArch64 ELF，包括可执行文件、PIE 和共享库，并将已 strip 的输入视为默认情况。导出快照按目标类别提供带阶段标签的启动路线，而非声称恢复完整执行顺序：可执行文件／PIE 收集适用的 `DT_PREINIT_ARRAY`、`DT_INIT`、`DT_INIT_ARRAY`、ELF 入口点和已确认的 `main`；`main` 仅在存在符号或识别到标准 bionic CRT 向 `__libc_init` 直接传递的地址时写入。共享库收集适用的 `DT_INIT`、`DT_INIT_ARRAY` 和可识别的 `JNI_OnLoad`。Agent 再沿可验证调用边按需展开。导出器不预先恢复 `RegisterNatives` 映射，也不预先计算可达函数切片；节名仅作为辅助线索。我们以窄范围换取对 Android AArch64 ELF 启动元数据的可靠处理；其他格式、多架构和运行时路径恢复留待以后。

归档
不用的
文档

--- update 2023-12-10
# 规则优化

规则检查，www.notion.so会走proxy，奇怪！
- 在规则中存在 「.SO」proxy在前，「notion.so」direct在后
- clashx meta 执行逻辑问先到先得，导致会先命中「.so」规则走proxy
- loon规则同clashx meta
- 小火箭 执行逻辑为会优先使用精度匹配，会先匹配到「notion.so」走direct
- QX的有「分流优化」执行逻辑为会优先使用精度匹配。

增加一个文件，用于剔除不要的规则，如这里的「.SO」proxy


规则脚本自动提交刀git； --- done

自动执行时无法删除文件夹原因（不行的话，删除这块改为shell脚本定时执行）
- 在cron定时执行时，`dirs = [p for p in paths if os.path.isdir(p)]` 这里获取文件夹失败。cron定时器中，需要将`os.path.isdir`拼接为绝对路径。
- 但是，单独执行该脚本，可以正常执行。

```python
def check_folders():
    """ 存储的数据大小，超过5天就删除否则删除旧的 """

    paths = os.listdir(current_path)

    dirs = [p for p in paths if os.path.isdir(p)]
```

--- done

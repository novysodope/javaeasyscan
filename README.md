```bash
███████╗██╗   ██╗██████╗  ██████╗
██╔════╝██║   ██║██╔══██╗██╔═══██╗
█████╗  ██║   ██║██████╔╝██║   ██║
██╔══╝  ██║   ██║██╔═══╝ ██║   ██║
██║     ╚██████╔╝██║     ╚██████╔╝
╚═╝      ╚═════╝ ╚═╝      ╚═════╝
                       JAVAEASYSCANNER  Fupo's series
—————————————————————————————————————————————————————
```
致力于解放大脑，方便双手

富婆系列，不想努力就用它

# JAVA审计辅助工具
本工具以辅助审计***Springboot/Springmvc项目为主***，效果更佳
## 工具实现思路：

java环境：JDK1.8

使用反向跟进的方法，定位漏洞点 ⟶ 定位漏洞所属方法、所属类 ⟶ 往上查找所属类及所属方法被调用的地方 ⟶ 直至没有被调用为止

**示例:**

有一个SQL注入的场景如下
```java
  <select id="selectUser" resultType="com.javavul.javavulpoj.data.SubUsers">
        select * from subusers where id = ${id}
    </select>
```
首先记录`selectUser`，以及所在的Mappper，根据Mapper配置找到对应的Mapper接口
```java
@Mapper
public interface ProductMapper {

    List<Product> selectUser(ProductExample example);
}
```
随后记录`ProductMapper`接口以及`selectUser`方法，接着往上找到调用该接口和方法的地方
```java
public class ProductServiceImpl implements ProductService {
    @Autowired
    private ProductMapper productMapper;
   public List<Product>  selectUser(ProductExample example) {
        return productMapper.selectUser(example);
    }
```
随后记录ProductServiceImpl类、selectUser方法和ProductService，然后往前找调用了ProductService.selectUser的地方
```java
@ResponseBody
    @RequestMapping("/sqlin")
    public List sqlin(HttpServletRequest req, HttpServletResponse rep, ProductExample example) throws IOException {
        String v = req.getParameter("sql");
        try {
            List reta = productService.selectUser(example);
            return ret;
        } catch (Exception e) {
           return Collections.singletonList(e.getMessage());
        }
    }
```
这个跟进的操作会重复到往上再没有调用，且如果mybatsic xml文件存在注入写法，但是方法没有被调用，则工具就会忽略该场景

等所有漏洞扫描完后，会在当前目录生成一个***HTML报告***，报告示例：

![image](https://github.com/novysodope/javaeasyscan/assets/45167857/6e299953-fe42-4aa0-b96d-b0786f638655)

![image](https://github.com/novysodope/javaeasyscan/assets/45167857/71e07f90-44d4-4ea8-9e73-74334d5d379e)

# 计划
因为时间仓促，本工具只写了mybatsic的SQL注入、JDBC拼接SQL注入、Fastjson反序列化、Groovy代码执行、命令注入五个模块，目前mybatsic的SQL注入模块比较完善

## 后续需要优化的地方：
- 所有模块增加入参校验，如果参数不可控则忽略场景，减少误报
- JDBC拼接导致的注入需要增加调用链跟踪（目前只是输出了存在拼接的地方）
- Fastjson反序列化增加版本检测
- this.method没有被识别，会影响调用链跟踪

## 后续新增
- 各种漏洞模块
- 界面？

# 其他
- 如果打包没有把依赖打包进去，请查看 [解决maven打jar包时不把依赖打包进去的问题](https://blog.csdn.net/qq_30786785/article/details/125506886)
- 因为要带项目了，所以要视情况挤时间出来更新，如果你有想法等不及的话可以下载代码改或者加入本项目直接pull更新或者提交issues，我会不定期查看，谢谢

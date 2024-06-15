package org.fupo.javaeasyscan;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.model.resolution.TypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @Describe SQL注入审计模块
 * @Author novy
 * @Version 1.0
 * @CreateDate 2024/6/13 14:53
 **/

public class SQLInjectScan {
    public static String topic = "SQL注入";
    private static final Logger logger = LoggerFactory.getLogger(SQLInjectScan.class);

    public static ResultUtil resultUtil;

    // 优化输出，显示完整的调用链
    static class VulnerabilityDetail {
        String xmlFile;
        String methodName;
        int xmlLineNumber;
        String vulnerableLineContent;
        List<String> implCalls;
        List<String> controllerCalls;

        VulnerabilityDetail(String xmlFile, String methodName, int xmlLineNumber, String vulnerableLineContent) {
            this.xmlFile = xmlFile;
            this.methodName = methodName;
            this.xmlLineNumber = xmlLineNumber;
            this.vulnerableLineContent = vulnerableLineContent;
            this.implCalls = new ArrayList<>();
            this.controllerCalls = new ArrayList<>();
        }

        void addImplCall(String call) {
            this.implCalls.add(call);
        }

        void addControllerCall(String call) {
            this.controllerCalls.add(call);
        }

        List<String> getFormattedOutput() {
            List<String> outputs = new ArrayList<>();
            String base = String.format("%s 的 %s 方法存在注入，在第 %d 行：%n<pre style=\"color:red;\">%s</pre>%n", xmlFile, methodName, xmlLineNumber, vulnerableLineContent);

            if (implCalls.isEmpty() && controllerCalls.isEmpty()) {
                outputs.add(base);
            } else {
                for (String implCall : implCalls) {
                    String implChain = base + implCall;
                    if (controllerCalls.isEmpty()) {
                        outputs.add(implChain);
                    } else {
                        for (String controllerCall : controllerCalls) {
                            outputs.add(implChain +  controllerCall);
                        }
                    }
                }
            }

            return outputs;
        }
    }

    public static void main(String[] args) throws Exception {
        File rootDir = new File(args[0]);
        logger.info("project: " + rootDir.getAbsolutePath());
        List<File> xmlFiles = new ArrayList<>();
        collectXmlFiles(rootDir, xmlFiles);

        // 用来存储解析到的Mapper接口名和他的文件路径，方便后续去查找对应的调用
        Map<String, String> namespaceToPathMap = new HashMap<>();
        Map<String, List<VulnerabilityDetail>> namespaceToVulnerabilitiesMap = new HashMap<>();

        for (File xmlFile : xmlFiles) {
            scanMyBatisXML(xmlFile, namespaceToPathMap, namespaceToVulnerabilitiesMap);
            logger.info("scan xml file: " + xmlFile.getName());
        }
        List<File> javaFiles = new ArrayList<>();

        // 确认Mapper接口文件中存在XML文件里存在漏洞的方法，这个操作是确保这个方法出现在整个数据库操作流程中（保证他被用到），减少误报
        collectJavaFiles(rootDir, javaFiles);
        for (Map.Entry<String, String> entry : namespaceToPathMap.entrySet()) {
            String namespace = entry.getKey();
            String xmlFilePath = entry.getValue();
            List<VulnerabilityDetail> vulnerabilities = namespaceToVulnerabilitiesMap.get(namespace);
            findMapperInterface(namespace, xmlFilePath, javaFiles, vulnerabilities);
        }

        Map<String, List<VulnerabilityDetail>> interfaceToVulnerabilitiesMap = findImplementationsAndMethodCalls(namespaceToVulnerabilitiesMap, javaFiles);
        findRequestMappingCalls(interfaceToVulnerabilitiesMap, javaFiles);

        List<String> results = new ArrayList<>();
        for (List<VulnerabilityDetail> vulnerabilities : namespaceToVulnerabilitiesMap.values()) {
            for (VulnerabilityDetail vulnerability : vulnerabilities) {
                List<String> outputs = vulnerability.getFormattedOutput();
                results.addAll(outputs);
            }
        }

        if (results!=null || !results.equals("")) {
            resultUtil.generateHtmlReport(results,topic);
        }else {
            System.out.println("\nnot found result\n");
        }
    }

    public static void collectXmlFiles(File dir, List<File> xmlFiles) {
        if (dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                collectXmlFiles(file, xmlFiles);
            }
        } else {
            if (dir.getName().endsWith(".xml")) {
                xmlFiles.add(dir);
            }
        }
    }

    public static void collectJavaFiles(File dir, List<File> javaFiles) {
        if (dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                collectJavaFiles(file, javaFiles);
            }
        } else {
            if (dir.getName().endsWith(".java")) {
                javaFiles.add(dir);
            }
        }
    }

    public static void scanMyBatisXML(File xmlFile, Map<String, String> namespaceToPathMap, Map<String, List<VulnerabilityDetail>> namespaceToVulnerabilitiesMap) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(xmlFile));

        String namespace = null;
        int currentLine = 0;

        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.START_ELEMENT) {
                String elementName = reader.getLocalName();
                if ("mapper".equals(elementName)) {
                    namespace = reader.getAttributeValue(null, "namespace");
                    if (namespace != null) {
                        namespaceToPathMap.put(namespace, xmlFile.getAbsolutePath());
                        namespaceToVulnerabilitiesMap.put(namespace, new ArrayList<>());
                    }
                } else if (Arrays.asList("select", "insert", "update", "delete").contains(elementName)) {
                    String id = reader.getAttributeValue(null, "id");
                    String sql = getElementText(reader);
                    currentLine = reader.getLocation().getLineNumber();

                    if (sql.contains("${")) {
                        logger.info("find sqlinject: " + sql);
                        if (namespace != null) {
                            logger.info("location: " + namespace);
                            namespaceToVulnerabilitiesMap.get(namespace).add(new VulnerabilityDetail(xmlFile.getName(), id, currentLine, sql.trim()));
                        }
                    }
                }
            }
        }
    }

    private static String getElementText(XMLStreamReader reader) throws XMLStreamException {
        StringBuilder content = new StringBuilder();
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.CHARACTERS) {
                content.append(reader.getText());
            } else if (event == XMLStreamConstants.END_ELEMENT) {
                break;
            }
        }
        return content.toString();
    }

    public static void findMapperInterface(String namespace, String xmlFilePath, List<File> javaFiles, List<VulnerabilityDetail> vulnerabilities) {
        String interfaceName = namespace.substring(namespace.lastIndexOf('.') + 1) + ".java";

        for (File javaFile : javaFiles) {
            if (javaFile.getName().equals(interfaceName)) {
                List<String> lines;
                try {
                    lines = Files.readAllLines(javaFile.toPath());
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }

                for (VulnerabilityDetail vulnerability : vulnerabilities) {
                    for (int i = 0; i < lines.size(); i++) {
                        String line = lines.get(i).trim();
                        if (line.startsWith("public") && line.contains(vulnerability.methodName + "(")) {
                            break;
                        }
                    }
                }
                break;
            }
        }
    }

    // 查找所有实现类，并且找到调用了上面有漏洞的Mapper方法的地方
    public static Map<String, List<VulnerabilityDetail>> findImplementationsAndMethodCalls(Map<String, List<VulnerabilityDetail>> namespaceToVulnerabilitiesMap, List<File> javaFiles) {
        Map<String, List<VulnerabilityDetail>> interfaceToVulnerabilitiesMap = new HashMap<>();

        for (File javaFile : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(javaFile);
                cu.accept(new VoidVisitorAdapter<Void>() {
                    @Override
                    public void visit(ClassOrInterfaceDeclaration classOrInterface, Void arg) {
                        super.visit(classOrInterface, arg);
                        if (!classOrInterface.isInterface() && classOrInterface.getImplementedTypes().size() > 0) {
                            String className = classOrInterface.getNameAsString();
                            // 这个implementedInterfaces后续会用到，因为最终控制层调用的就是接口的方法，所以这里要先找到实现类实现的接口，以方便后续的调用查找
                            List<String> implementedInterfaces = new ArrayList<>();
                            classOrInterface.getImplementedTypes().forEach(implementedType -> {
                                implementedInterfaces.add(implementedType.getNameAsString());
                            });

                            classOrInterface.getMethods().forEach(method -> {
                                method.accept(new VoidVisitorAdapter<Void>() {
                                    @Override
                                    public void visit(MethodCallExpr methodCall, Void arg) {
                                        super.visit(methodCall, arg);
                                        methodCall.getScope().ifPresent(scope -> {
                                            namespaceToVulnerabilitiesMap.forEach((namespace, vulnerabilities) -> {
                                                String mapperInterfaceName = namespace.substring(namespace.lastIndexOf('.') + 1);
                                                if (mapperInterfaceName != null && vulnerabilities.stream().anyMatch(v -> v.methodName.equals(methodCall.getNameAsString()))) {
                                                    boolean found = false;
                                                    String fullMethodName = mapperInterfaceName.toLowerCase() + "." + methodCall.getNameAsString().toLowerCase();
                                                    try {
                                                        List<String> lines = Files.readAllLines(javaFile.toPath());
                                                        for (String line : lines) {
                                                            if (line.toLowerCase().contains(fullMethodName)) {
                                                                found = true;
                                                                break;
                                                            }
                                                        }
                                                    } catch (IOException e) {
                                                        e.printStackTrace();
                                                    }
                                                    if (found) {
                                                        VulnerabilityDetail vulnerability = vulnerabilities.stream().filter(v -> v.methodName.equals(methodCall.getNameAsString())).findFirst().orElse(null);
                                                        if (vulnerability != null) {
                                                            String vulnerableLineContent = getLineContent(javaFile, methodCall.getBegin().get().line - 1);
                                                            vulnerability.addImplCall(String.format("<b>调用信息如下:</b>%n%n%s 类实现了接口 %s , 该实现类调用了 %s 的 %s 方法：%n<pre style=\"color:red;\">%s</pre>%n", className, String.join(", ", implementedInterfaces), mapperInterfaceName, methodCall.getNameAsString(),vulnerableLineContent));
                                                            logger.info("mapper: " + mapperInterfaceName);
                                                            logger.info("methodName: " + vulnerability.methodName);
                                                            logger.info("interfece: " + implementedInterfaces);
                                                            logger.info("implements: " + className);
                                                            implementedInterfaces.forEach(interfaceName -> {
                                                                interfaceToVulnerabilitiesMap.putIfAbsent(interfaceName, new ArrayList<>());
                                                                interfaceToVulnerabilitiesMap.get(interfaceName).add(vulnerability);
                                                            });
                                                        }
                                                    }
                                                }
                                            });
                                        });
                                    }
                                }, null);
                            });
                        }
                    }
                }, null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return interfaceToVulnerabilitiesMap;
    }

    // 参考的springboot/mvc项目，基于注解来找控制层，在控制层里找接口
    public static void findRequestMappingCalls(Map<String, List<VulnerabilityDetail>> interfaceToVulnerabilitiesMap, List<File> javaFiles) {
        for (File javaFile : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(javaFile);
                cu.accept(new VoidVisitorAdapter<Void>() {
                    @Override
                    public void visit(ClassOrInterfaceDeclaration classOrInterface, Void arg) {
                        super.visit(classOrInterface, arg);
                        if (classOrInterface.getAnnotations().stream().anyMatch(annotation -> annotation.getNameAsString().equals("RequestMapping")
                                || annotation.getNameAsString().equals("GetMapping")
                                || annotation.getNameAsString().equals("PostMapping")
                                || annotation.getNameAsString().equals("PutMapping")
                                || annotation.getNameAsString().equals("DeleteMapping")
                                || annotation.getNameAsString().equals("Controller"))) {
                            String controllerClassName = classOrInterface.getNameAsString();

                            classOrInterface.getMethods().forEach(method -> {
                                method.accept(new VoidVisitorAdapter<Void>() {
                                    @Override
                                    public void visit(MethodCallExpr methodCall, Void arg) {
                                        super.visit(methodCall, arg);
                                        methodCall.getScope().ifPresent(scope -> {
                                            String calledInterfaceName = scope.toString();
                                            interfaceToVulnerabilitiesMap.forEach((interfaceName, vulnerabilities) -> {
                                                vulnerabilities.forEach(vulnerability -> {
                                                    String intfmet = (interfaceName + "." + vulnerability.methodName).toLowerCase();
                                                    String met = methodCall.toString().toLowerCase();
                                                    if (interfaceName != null && met.contains(intfmet)) {
                                                        String vulnerableLineContent = getLineContent(javaFile, methodCall.getBegin().get().line - 1);
                                                        vulnerability.addControllerCall(String.format("往上跟进被实现的接口发现，%s 类的 %s 方法调用了被实现接口 %s 的 %s 方法，在第 %d 行：%n<pre style=\"color:red;\">%s</pre>%n",
                                                                controllerClassName, method.getNameAsString(), interfaceName, methodCall.getNameAsString(), methodCall.getBegin().get().line, vulnerableLineContent));
                                                        logger.info("controller: " + controllerClassName);
                                                    }
                                                });
                                            });
                                        });
                                    }
                                }, null);
                            });
                        }
                    }
                }, null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static String getLineContent(File file, int lineNumber) {
        try {
            List<String> lines = Files.readAllLines(file.toPath());
            if (lineNumber >= 0 && lineNumber < lines.size()) {
                return lines.get(lineNumber).trim();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

}

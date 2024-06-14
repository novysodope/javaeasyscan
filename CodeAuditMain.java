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

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * @author novy
 * @version 1.0
 * @createDate 2024/6/13 14:53
 **/
public class CodeAuditMain {

    public static void main(String[] args) throws Exception {
        File rootDir = new File(args[0]);
        List<File> xmlFiles = new ArrayList<>();
        collectXmlFiles(rootDir, xmlFiles);
        //用来存储解析到的Mapper接口名和他的文件路径，方便后续去查找对应的调用
        Map<String, String> namespaceToPathMap = new HashMap<>();
        Map<String, List<String>> namespaceToVulnerableMethodsMap = new HashMap<>();

        for (File xmlFile : xmlFiles) {
            scanMyBatisXML(xmlFile, namespaceToPathMap, namespaceToVulnerableMethodsMap);
        }

        List<File> javaFiles = new ArrayList<>();
        collectJavaFiles(rootDir, javaFiles);
        //确认Mapper接口文件中存在XML文件里存在漏洞的方法，这个操作是确保这个方法出现在整个数据库操作流程中（保证他被用到），减少误报
        for (Map.Entry<String, String> entry : namespaceToPathMap.entrySet()) {
            String namespace = entry.getKey();
            String xmlFilePath = entry.getValue();
            List<String> vulnerableMethods = namespaceToVulnerableMethodsMap.get(namespace);
            findMapperInterface(namespace, xmlFilePath, javaFiles, vulnerableMethods);
        }

        findImplementationsAndMethodCalls(namespaceToVulnerableMethodsMap, javaFiles);
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

    //找注入的实现
    public static void scanMyBatisXML(File xmlFile, Map<String, String> namespaceToPathMap, Map<String, List<String>> namespaceToVulnerableMethodsMap) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(xmlFile));

        String namespace = null;

        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.START_ELEMENT) {
                String elementName = reader.getLocalName();
                if ("mapper".equals(elementName)) {
                    namespace = reader.getAttributeValue(null, "namespace");
                    if (namespace != null) {
                        namespaceToPathMap.put(namespace, xmlFile.getAbsolutePath());
                        namespaceToVulnerableMethodsMap.put(namespace, new ArrayList<>());
                    }
                } else if (Arrays.asList("select", "insert", "update", "delete").contains(elementName)) {
                    String id = reader.getAttributeValue(null, "id");
                    String sql = getElementText(reader);
                    int lineNumber = reader.getLocation().getLineNumber();

                    if (sql.contains("${")) {
                        System.out.printf("%s 的 %s 方法存在注入，在第 %d 行%n", xmlFile.getName(), id, lineNumber);
                        if (namespace != null) {
                            namespaceToVulnerableMethodsMap.get(namespace).add(id);
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

    public static void findMapperInterface(String namespace, String xmlFilePath, List<File> javaFiles, List<String> vulnerableMethods) {
        String interfaceName = namespace.substring(namespace.lastIndexOf('.') + 1) + ".java";

        for (File javaFile : javaFiles) {
            if (javaFile.getName().equals(interfaceName)) {
                boolean foundVulnerableMethod = false;
                List<String> lines;
                try {
                    lines = Files.readAllLines(javaFile.toPath());
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }

                for (String methodName : vulnerableMethods) {
                    for (int i = 0; i < lines.size(); i++) {
                        String line = lines.get(i).trim();
                        if (line.startsWith("public") && line.contains(methodName + "(")) {
                            if (!foundVulnerableMethod) {
                                System.out.printf("%s 对应的接口文件：%s%n", Paths.get(xmlFilePath).getFileName(), javaFile.getAbsolutePath());
                                foundVulnerableMethod = true;
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    //查找所有实现类，并且找到调用了上面有漏洞的Mapper方法的地方
    public static void findImplementationsAndMethodCalls(Map<String, List<String>> namespaceToVulnerableMethodsMap, List<File> javaFiles) {
        for (File javaFile : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(javaFile);
                cu.accept(new VoidVisitorAdapter<Void>() {
                    @Override
                    public void visit(ClassOrInterfaceDeclaration classOrInterface, Void arg) {
                        super.visit(classOrInterface, arg);
                        if (!classOrInterface.isInterface() && classOrInterface.getImplementedTypes().size() > 0) {
                            String className = classOrInterface.getNameAsString();
                            //这个implementedInterfaces后续会用到，因为最终业务逻辑层调用的就是接口的方法，所以这里要先找到实现类实现的接口，以方便后续的调用查找
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
                                            namespaceToVulnerableMethodsMap.forEach((namespace, vulnerableMethods) -> {
                                                String mapperInterfaceName = namespace.substring(namespace.lastIndexOf('.') + 1);
                                                if (mapperInterfaceName!=null&& vulnerableMethods.contains(methodCall.getNameAsString())) {
                                                    System.out.printf("%s 类实现了接口 %s , 调用了 %s 的 %s 方法，在 %d 行%n",
                                                            className,String.join(", ", implementedInterfaces), mapperInterfaceName, methodCall.getNameAsString(), methodCall.getBegin().get().line);
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
    }
}

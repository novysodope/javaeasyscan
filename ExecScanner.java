public class ExecScanner {

    public static void main(String[] args) {
        File rootDir = new File(args[0]);
        if (!rootDir.isDirectory()) {
            System.err.println("Provided path is not a directory.");
            return;
        }

        scanJavaFiles(rootDir);
    }

    public static void scanJavaFiles(File dir) {
        List<File> javaFiles = getJavaFiles(dir);
        CombinedTypeSolver combinedTypeSolver = new CombinedTypeSolver();
        combinedTypeSolver.add(new ReflectionTypeSolver());
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedTypeSolver);
        ParserConfiguration parserConfiguration = new ParserConfiguration().setSymbolResolver(symbolSolver);
        JavaParser javaParser = new JavaParser(parserConfiguration);

        for (File javaFile : javaFiles) {
            try {
                CompilationUnit cu = javaParser.parse(javaFile).getResult().get();
                MethodCallVisitor methodCallVisitor = new MethodCallVisitor();
                methodCallVisitor.visit(cu, javaFile.getAbsolutePath());
            } catch (IOException e) {
                System.err.println("Failed to parse file: " + javaFile.getAbsolutePath());
                e.printStackTrace();
            }
        }
    }

    public static List<File> getJavaFiles(File dir) {
        List<File> javaFiles = new ArrayList<>();
        if (dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                if (file.isDirectory()) {
                    javaFiles.addAll(getJavaFiles(file));
                } else if (file.getName().endsWith(".java")) {
                    javaFiles.add(file);
                }
            }
        }
        return javaFiles;
    }

    private static class MethodCallVisitor extends VoidVisitorAdapter<String> {
        private final Map<String, String> variableDeclarations = new HashMap<>();
        private String currentMethodName = "";
        private String currentClassName = "";

        @Override
        public void visit(ClassOrInterfaceDeclaration classOrInterface, String filePath) {
            currentClassName = classOrInterface.getNameAsString();
            super.visit(classOrInterface, filePath);
        }

        @Override
        public void visit(MethodDeclaration methodDeclaration, String filePath) {
            currentMethodName = methodDeclaration.getNameAsString();
            super.visit(methodDeclaration, filePath);
        }

        @Override
        public void visit(VariableDeclarator variableDeclarator, String filePath) {
            super.visit(variableDeclarator, filePath);
            if (variableDeclarator.getInitializer().isPresent()) {
                Expression initializer = variableDeclarator.getInitializer().get();
                if (initializer.isMethodCallExpr()) {
                    MethodCallExpr methodCall = initializer.asMethodCallExpr();
                    if (methodCall.getNameAsString().equals("getRuntime") && methodCall.getScope().isPresent() && methodCall.getScope().get().toString().equals("Runtime")) {
                        variableDeclarations.put(variableDeclarator.getNameAsString(), "Runtime.getRuntime()");
                    }
                } else if (initializer.isObjectCreationExpr()) {
                    ObjectCreationExpr objectCreationExpr = initializer.asObjectCreationExpr();
                    if (objectCreationExpr.getType().getNameAsString().equals("ProcessBuilder")) {
                        variableDeclarations.put(variableDeclarator.getNameAsString(), "new ProcessBuilder()");
                    }
                }
            }
        }

        @Override
        public void visit(AssignExpr assignExpr, String filePath) {
            super.visit(assignExpr, filePath);
            if (assignExpr.getTarget().isNameExpr() && assignExpr.getValue().isMethodCallExpr()) {
                String variableName = assignExpr.getTarget().asNameExpr().getNameAsString();
                MethodCallExpr methodCall = assignExpr.getValue().asMethodCallExpr();
                if (methodCall.getNameAsString().equals("getRuntime") && methodCall.getScope().isPresent() && methodCall.getScope().get().toString().equals("Runtime")) {
                    variableDeclarations.put(variableName, "Runtime.getRuntime()");
                }
            } else if (assignExpr.getTarget().isNameExpr() && assignExpr.getValue().isObjectCreationExpr()) {
                String variableName = assignExpr.getTarget().asNameExpr().getNameAsString();
                ObjectCreationExpr objectCreationExpr = assignExpr.getValue().asObjectCreationExpr();
                if (objectCreationExpr.getType().getNameAsString().equals("ProcessBuilder")) {
                    variableDeclarations.put(variableName, "new ProcessBuilder()");
                }
            }
        }

        @Override
        public void visit(MethodCallExpr methodCall, String filePath) {
            if (methodCall.getNameAsString().equals("exec")) {
                int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                System.out.println("找到了包含有exec方法的类: " + filePath + " at line " + lineNumber);
                System.out.println("它所属的方法是： " + currentMethodName + "方法，这个" + currentMethodName + "方法属于: " + currentClassName + "类");
            } else if (methodCall.getNameAsString().equals("start")) {
                if (isProcessBuilderStartMethod(methodCall)) {
                    int lineNumber = methodCall.getBegin().isPresent() ? methodCall.getBegin().get().line : -1;
                    System.out.println("找到了包含有start方法的类: " + filePath + " at line " + lineNumber);
                    System.out.println("这个代码所属的方法是： " + currentMethodName + "，这个" + currentMethodName + "方法属于: " + currentClassName + "类");
                }
            }
            super.visit(methodCall, filePath);
        }

        private boolean isProcessBuilderStartMethod(MethodCallExpr methodCall) {
            try {
                return methodCall.resolve().getQualifiedSignature().contains("java.lang.ProcessBuilder.start");
            } catch (Exception e) {
                return false;
            }
        }
    }
}

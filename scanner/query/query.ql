
/**
 * @name Find Public Function Declarations
 * @description Finds function declarations, their parameters, and locations.
 * @kind table
 * @id cpp/custom/find-function-declarations
 */
import cpp

from Function f
where
    f.getLocation().getFile().getAbsolutePath().matches("%/home/user/crypto_library_scanner_and_categoryzer%")
select
    f.getNamespace().getQualifiedName() as namespace,
    f.getName() as functionName,
    f.getType().toString() as returnType,
    f.getParameterString() as parameterString,
    f.getLocation().getFile().getAbsolutePath() as filePath,
    f.getLocation().getStartLine() as startLine
order by
    filePath, startLine
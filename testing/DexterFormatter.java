import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public class DexterFormatter extends Formatter {

  @Override
  public String format(LogRecord record) {
    return "[" + record.getThreadID() + "] "
      + record.getLevel() + " "
      + record.getSourceClassName() + "."
      + record.getSourceMethodName() + ": "
      + record.getMessage() + "\n";
  }
}
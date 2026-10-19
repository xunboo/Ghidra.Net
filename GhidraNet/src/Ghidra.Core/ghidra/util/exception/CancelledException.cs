namespace ghidra.util.exception;

/**
 * CancelledException indicates that the user cancelled the current operation.
 */
public class CancelledException : UsrException
{
    public const string DEFAULT_MESSAGE = "Operation cancelled";

    /**
     * Default constructor. Message indicates 'Operation cancelled'.
     */
    public CancelledException() : base(DEFAULT_MESSAGE)
    {
    }

    public CancelledException(string msg) : base(msg)
    {
    }

    /**
     * true if the message of this exception is DEFAULT_MESSAGE
     */
    public bool isDefaultMessage()
    {
        return Message == DEFAULT_MESSAGE;
    }
}

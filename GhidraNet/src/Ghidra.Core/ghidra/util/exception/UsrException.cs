namespace ghidra.util.exception;

/**
 * Base Class for all ghidra non-runtime exceptions
 */
public class UsrException : Exception
{
    /**
     * Construct a new UsrException with no message
     */
    public UsrException() : base()
    {
    }

    /**
     * Construct a new UsrException with the given message
     * 
     * @param msg the exception message
     */
    public UsrException(string msg) : base(msg)
    {
    }

    /**
     * Construct a new UsrException with the given message and cause
     * 
     * @param msg the exception message
     * @param cause the exception cause
     */
    public UsrException(string msg, Exception cause) : base(msg, cause)
    {
    }
}

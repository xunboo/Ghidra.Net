namespace org.junit;

using System;
using Xunit;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class TestAttribute : FactAttribute
{
    public Type? expected { get; set; }
    public long timeout { get; set; }
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class BeforeAttribute : Attribute
{
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class AfterAttribute : Attribute
{
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class BeforeClassAttribute : Attribute
{
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class AfterClassAttribute : Attribute
{
}

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public class IgnoreAttribute : Attribute
{
    public string Reason { get; }
    public IgnoreAttribute(string reason = "") => Reason = reason;
}

[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Method, AllowMultiple = false)]
public class RuleAttribute : Attribute
{
}

[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Method, AllowMultiple = false)]
public class ClassRuleAttribute : Attribute
{
}

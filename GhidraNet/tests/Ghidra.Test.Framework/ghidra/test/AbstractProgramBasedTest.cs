namespace ghidra.test;

using System;

public abstract class AbstractProgramBasedTest : AbstractGhidraHeadlessIntegrationTest
{
    protected object? program;
    protected object? tool;

    public AbstractProgramBasedTest() : base()
    {
    }

    public virtual void initialize()
    {
        env = new TestEnv();
        tool = env.getTool();
    }

    public override void tearDown()
    {
        env?.dispose();
        env = null;
        base.tearDown();
    }

    public virtual void applyCmd(object? p, object? cmd) { }
    public virtual object addr(string hex) => hex;
    public virtual ghidra.util.datastruct.Set<docking.action.DockingActionIf> getActionsByOwnerAndName(object? tool, string owner, string name)
    {
        var set = new ghidra.util.datastruct.Set<docking.action.DockingActionIf>();
        set.add(getAction(tool, name));
        return set;
    }
}

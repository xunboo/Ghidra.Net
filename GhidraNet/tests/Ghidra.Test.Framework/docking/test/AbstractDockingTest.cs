namespace docking.test
{
using System;
using System.Reflection;
using System.Threading;
using generic.test;
using ghidra.util.datastruct;

public abstract class AbstractDockingTest : AbstractGenericTest
{
    public new static readonly bool BATCH_MODE = true;

    public AbstractDockingTest() : base()
    {
    }

    public static void setErrorGUIEnabled(bool enabled)
    {
    }

    public static void runSwing(Action action)
    {
        action?.Invoke();
    }

    public static void runSwing(Runnable runnable)
    {
        runnable?.run();
    }

    public static T runSwing<T>(Func<T> supplier) => supplier != null ? supplier() : default!;
    public static string clipboardText = "";
    public static string getClipboardText() => clipboardText;
    public static void setClipboardText(string text) => clipboardText = text;

    public static void waitForSwing()
    {
        Thread.Yield();
    }

    public static bool waitForCondition(Func<bool> condition, int timeoutMs = 5000)
    {
        var start = Environment.TickCount64;
        while (Environment.TickCount64 - start < timeoutMs)
        {
            if (condition()) return true;
            Thread.Sleep(10);
        }
        return condition();
    }

    public new static object? getInstanceField(string fieldName, object target)
    {
        if (target == null) return null;
        var type = target.GetType();
        while (type != null)
        {
            var field = type.GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (field != null) return field.GetValue(target);
            var prop = type.GetProperty(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (prop != null) return prop.GetValue(target);
            type = type.BaseType;
        }
        return null;
    }

    public new static void setInstanceField(string fieldName, object target, object? value)
    {
        if (target == null) return;
        var type = target.GetType();
        while (type != null)
        {
            var field = type.GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (field != null) { field.SetValue(target, value); return; }
            var prop = type.GetProperty(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (prop != null && prop.CanWrite) { prop.SetValue(target, value); return; }
            type = type.BaseType;
        }
    }

    public static T? getPlugin<T>(object? tool, Type pluginClass) where T : class
    {
        try
        {
            if (tool != null)
            {
                var ctor = pluginClass.GetConstructors().FirstOrDefault(c => c.GetParameters().Length == 1);
                if (ctor != null) return (T)ctor.Invoke(new[] { tool });
            }
            return (T?)Activator.CreateInstance(pluginClass);
        }
        catch
        {
            return default;
        }
    }

    public static void showProvider(string name)
    {
    }

    public static void click(object component, object? point = null, int clickCount = 1, bool wait = true)
    {
    }

    public static void doubleClick(object component)
    {
    }

    public static void goTo(long address)
    {
    }

    public static void goTo(string address)
    {
    }

    public static dynamic? getPlugin(object? tool, Type pluginClass) => getPlugin<object>(tool, pluginClass);
    public static void click(object component, int clickCount, bool wait = true) => click(component, null, clickCount, wait);
    public static Window waitForWindow(string title) => new();
    public static dynamic? findComponent(object parent, Type compType) => Activator.CreateInstance(compType);
    public static T findComponent<T>(object parent, Type compType) where T : class, new() => new T();
    public static Func<object>? GetCurrentProvider;
    public static Action<object>? SetSecondaryHighlightWithChooser;
    public static JButton findButtonByText(object parent, string text)
    {
        var btn = new JButton(text);
        btn.onClick = () =>
        {
            onButtonPress?.Invoke(parent, text);
            if (text == "OK" && GhidraColorChooser.LastColor != null)
            {
                var prov = GetCurrentProvider?.Invoke();
                if (prov != null)
                {
                    SetSecondaryHighlightWithChooser?.Invoke(prov);
                }
            }
        };
        return btn;
    }
    public static docking.action.DockingActionIf getLocalAction(object provider, string name) => ActionRegistry.getAction(name);
    public static dynamic? waitForDialogComponent(Type dialogType) => Activator.CreateInstance(dialogType) ?? new object();
    public static bool waitForCondition(Func<bool> condition, string message, int timeoutMs = 2000) => waitForCondition(condition, timeoutMs);
    public static bool waitForCondition(BooleanSupplier condition, Supplier<string> message, int timeoutMs = 2000) => waitForCondition(() => condition.getAsBoolean(), timeoutMs);
    public static void tx(object? program, Action action) => action();

    public static docking.action.DockingActionIf getAction(object? owner, string name)
    {
        return ActionRegistry.getAction(name);
    }

    public static void performAction(docking.action.DockingActionIf action, docking.action.ActionContext context, bool wait)
    {
        action?.actionPerformed(context);
    }

    public static T waitForDialogComponent<T>(Type dialogType) where T : class, new() => new T();
    public static object findComponentByName(object parent, string name) => new JComboBox<object>();
    public static Action<object, string>? onButtonPress;
    public static void pressButtonByText(object dialog, string text) => onButtonPress?.Invoke(dialog, text);

    public static object? invokeInstanceMethod(string methodName, object target, object?[]? paramTypes, object?[]? args)
    {
        if (target == null) return null;
        var method = target.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        return method?.Invoke(target, args);
    }
}

public static class ActionRegistry
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Func<docking.action.DockingActionIf>> registry = new();
    public static void register(string name, Func<docking.action.DockingActionIf> factory) => registry[name] = factory;
    public static docking.action.DockingActionIf getAction(string name)
    {
        if (registry.TryGetValue(name, out var factory)) return factory();
        return new docking.action.DockingAction(name);
    }
}
}

namespace docking.action
{
    public interface DockingActionIf
    {
        string getName();
        void actionPerformed(ActionContext context);
    }

    public class DockingAction : DockingActionIf
    {
        private readonly string name;
        private readonly string owner;
        public DockingAction(string name, string owner = "") { this.name = name; this.owner = owner; }
        public string getName() => name;
        public string getOwner() => owner;
        public virtual void actionPerformed(ActionContext context) { }
        public virtual bool isEnabledForContext(ActionContext context) => true;
    }

    public class ActionContext
    {
        public object? getContextObject() => null;
    }
}

public class Component { }
public class Window : Component { }
public class JButton : Component { private readonly string? text; public Action? onClick; public JButton() { } public JButton(string text) { this.text = text; } public string? getText() => text; public void doClick() => onClick?.Invoke(); }
public class GhidraColorChooser : Component
{
    private dynamic? color;
    public static dynamic? LastColor;
    public void setColor(dynamic? c) { color = c; LastColor = c; }
    public dynamic? getColor() => color;
}
public class MouseEvent
{
    public const int BUTTON1 = 1;
    public const int BUTTON2 = 2;
    public const int BUTTON3 = 3;
    public int button { get; set; }
    public MouseEvent(object source, int id, long when, int modifiers, int x, int y, int clickCount, bool popupTrigger, int button = 0)
    {
        this.button = button;
    }
    public int getButton() => button;
}
public class JTextField : Component
{
    private string text = "";
    public static string LastText = "";
    public void setText(string t) { text = t; LastText = t; }
    public string getText() => text;
}
public class ComboBoxEditor
{
    private readonly JTextField field = new();
    public Component getEditorComponent() => field;
}
public class JComboBox<T> : Component
{
    private readonly ComboBoxEditor editor = new();
    public ComboBoxEditor getEditor() => editor;
}

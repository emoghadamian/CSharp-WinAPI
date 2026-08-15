using CSharp.WinAPI.Tasks;
using ScheduledTaskInspection;

var inspector = new ScheduledTaskInspector();
var tasks = inspector.EnumerateTasks();
Console.WriteLine($"Tasks returned: {tasks.Count}");
foreach (var task in tasks.Take(30))
{
    Console.WriteLine($"{task.Path} state={task.State.Value} enabled={task.Enabled} principal={task.Principal.UserId ?? task.Principal.GroupId ?? "<none>"}");
    Console.WriteLine($"  settings: hidden={task.Settings.Hidden}, demand={task.Settings.AllowDemandStart}, priority={task.Settings.Priority}");
    foreach (var trigger in task.Triggers.Take(4)) Console.WriteLine($"  trigger: raw-type={trigger.RawType}, enabled={trigger.Enabled}, start={trigger.StartBoundary ?? "<none>"}");
    foreach (var action in task.Actions.Take(4)) Console.WriteLine($"  action: raw-type={action.RawType}, path={action.Path ?? action.ClassId ?? "<opaque>"}, args={action.Arguments ?? "<none>"}");
}
Console.WriteLine($"Raw COM example: {RawScheduledTask.DescribeFirstTask()}");

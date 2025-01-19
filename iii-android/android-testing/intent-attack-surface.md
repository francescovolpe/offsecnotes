# Intent Attack Surface

## <mark style="color:purple;">Introduction</mark>

An intent is an abstract description of an operation to be performed.

**Starting Activities**

<pre class="language-java"><code class="lang-java"><strong>// 1 way
</strong><strong>Intent intent = new Intent();
</strong>intent.setComponent(new ComponentName("com.package.test", "com.package.test.SecondActivity"));
startActivity(intent);
</code></pre>

```java
// 2 way
Intent intent = new Intent();
intent.setClassName("com.package.test", "com.package.test.SecondActivity");
startActivity(intent);
```

**Incoming Intent**

`getIntent()` is a method in Android used to retrieve the **Intent.**

## <mark style="color:purple;">Send intent with adb</mark>

```sh
# Syntax
adb shell am start -a <ACTION> -d <DATA> -n <PACKAGE>/<CLASS-COMPONENT>

# Example
adb shell am start -a com.package.action.GIVE_FLAG -d "https://test.com" -n com.package/com.package.test.MainActivity
```

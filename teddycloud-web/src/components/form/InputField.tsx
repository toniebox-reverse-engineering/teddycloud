import { useTranslation } from "react-i18next";
import { useField } from "formik";
import FormItem from "antd/es/form/FormItem";
import { Input, InputProps } from "antd";
import { ChangeEvent } from "react";

type InputFieldProps = {
  name: string;
  label?: string;
};

const InputField = (props: InputFieldProps & InputProps) => {
  const { t } = useTranslation();
  const { name, label, ...inputProps } = props;
  const [field, meta, helpers] = useField(name!);

  const hasFeedback = !!(meta.touched && meta.error);
  const help = meta.touched && meta.error && t(meta.error);
  const validateStatus = meta.touched && meta.error ? "error" : undefined;

  return (
    <FormItem
      help={hasFeedback ? help : undefined}
      validateStatus={validateStatus}
      label={label}
    >
      <Input
        {...inputProps}
        {...field}
        onChange={(event: ChangeEvent<HTMLInputElement>) => {
          fetch(`http://localhost/api/set/${name}`, {
            method: "POST",
            body: event.target.value,
            headers: {
              "Content-Type": "text/plain",
            },
          });
          helpers.setValue(
            event.target.value === null ? undefined : Number(event.target.value)
          );
        }}
      />
    </FormItem>
  );
};

export { InputField };

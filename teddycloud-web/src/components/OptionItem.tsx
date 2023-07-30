interface OptionItemProps {
  ID: string;
  type: string;
  description: string;
}

export const OptionItem = ({ ID, type, description }: OptionItemProps) => {
  const parts = ID.split(".");

  return (
    <div>
      {type}
      {ID}
      {description}
    </div>
  );
};

export default OptionItem;
